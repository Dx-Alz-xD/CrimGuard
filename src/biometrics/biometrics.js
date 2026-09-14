'use strict';

// Behavioural biometrics: learns how each account owner types and moves the pointer, and notices
// when someone else is.
//
// Each window from the browser is judged against the owner's profile (model.js) and moves the
// session's trust level. What that calls for is decided together with the latest risk score
// (src/identity/policy.js) and carried out by the identity throttle - a step-up for this session,
// or a freeze - so the response is recorded and enforced the same way as every other.
//
// dailyDeviation() gives the risk engine keystroke_cadence_deviation and mouse_velocity_deviation,
// measured against the person's own profile.

const { createSubjects } = require('../telemetry/subjects');
const { sessionRef } = require('../telemetry');
const { FEATURE_BY_KEY } = require('./features');
const { MODEL, buildProfile, verifyWindow, nextSessionState, dailyDeviation } = require('./model');
const { createBiometricStore } = require('./store');
const { biometricAction } = require('../identity/policy');
const { latestScore } = require('../identity/scores');

const SESSION_IDLE_MS = 12 * 60 * 60 * 1000;
const round = (value, places = 3) => (value === null || value === undefined ? null : Number(Number(value).toFixed(places)));

function createBiometrics(db, { identity, model = MODEL, now = Date.now } = {}) {
  if (!db) return createDisabled();
  if (!identity) throw new Error('Biometrics needs the identity throttle to act on what it sees.');

  const store = createBiometricStore(db);
  const subjects = createSubjects(db);
  const sessions = new Map(); // session ref -> trust state; the evidence, not the response
  const profiles = new Map(); // crimguard user id -> { key, profile }

  const refFor = (user, tokenHash) => sessionRef(tokenHash) || `red-user:${user.id}`;

  function stateFor(ref) {
    const t = now();
    for (const [key, state] of sessions) if (t - state.seenAt > SESSION_IDLE_MS) sessions.delete(key);
    let state = sessions.get(ref);
    if (!state) {
      state = { trust: 1, mismatches: 0, judged: 0, matchStreak: 0, escalated: null, seenAt: t };
      sessions.set(ref, state);
    }
    state.seenAt = t;
    return state;
  }

  // A confirmed step-up resets the evidence for that session.
  identity.onStepUpPassed(({ sessionRef: ref }) => {
    const state = ref && sessions.get(ref);
    if (state) Object.assign(state, { trust: 1, mismatches: 0, matchStreak: 0, escalated: null });
  });

  async function profileFor(userId) {
    const windows = await store.profileWindows(userId, model.maxProfileWindows * 2);
    const key = windows.length ? `${windows.length}:${windows[windows.length - 1].id}` : 'empty';
    const cached = profiles.get(userId);
    if (cached && cached.key === key) return cached.profile;
    const profile = buildProfile(windows, model);
    profiles.set(userId, { key, profile });
    return profile;
  }

  const enrolment = (profile) => ({
    enrolled: profile.enrolled,
    keys: profile.modalities.keys.enrolled,
    pointer: profile.modalities.pointer.enrolled,
    needed: profile.needed,
  });

  return {
    enabled: true,
    store,

    // One window from a signed-in session. Returns { verdict, decision, stepUp, frozen } - the
    // route tells the browser only the last two.
    async submit({ user, tokenHash, window }) {
      const userId = await subjects.forUser(user);
      const deviceId = window.fingerprint ? await subjects.forDevice(userId, window.fingerprint) : null;
      const ref = refFor(user, tokenHash);
      const state = stateFor(ref);
      const profile = await profileFor(userId);
      const standing = await identity.standingOf(userId, ref);

      const result = verifyWindow(profile, window.features, model);
      const next = nextSessionState(state, result, model);
      Object.assign(state, { trust: next.trust, mismatches: next.mismatches, judged: next.judged, matchStreak: next.matchStreak });

      // While a step-up is open, windows are judged and stored but can't teach the profile:
      // someone else must not type their way into being the owner.
      const stored = standing.stepUp && result.verdict === 'match' ? { ...result, verdict: 'uncertain' } : result;
      await store.insert({ userId, deviceId, sessionRef: ref, window, result: stored, trust: next.trust, decision: next.decision });

      let response = null;
      if (!standing.frozen && next.decision !== 'ok') {
        const risk = await latestScore(db, userId);
        const wanted = biometricAction(next, risk);
        // An open step-up already covers a step-up; only a freeze goes past it. Once per session
        // for each kind of response; a confirmed step-up clears it.
        const needed = wanted && (wanted.action === 'session_freeze' || !standing.stepUp);
        if (needed && state.escalated !== wanted.action) {
          state.escalated = wanted.action;
          response = await identity.respond({
            crimUserId: userId, action: wanted.action, source: 'biometrics', sessionRef: ref, risk,
            reasons: [wanted.reason, `trust ${round(next.trust, 2)}`, ...result.deviations.slice(0, 3)
              .map((d) => `${FEATURE_BY_KEY[d.key]?.label ?? d.key} ${d.z > 0 ? '+' : ''}${round(d.z, 1)}σ`)],
          });
        }
      }

      const after = response ? await identity.standingOf(userId, ref) : standing;
      return {
        verdict: result.verdict,
        distanceZ: round(result.distanceZ, 2),
        trust: round(next.trust),
        decision: next.decision,
        suddenChange: next.suddenChange,
        action: response?.action ?? null,
        stepUp: after.stepUp,
        frozen: after.frozen,
        enrolment: enrolment(profile),
      };
    },

    // The deviation for one person's day, per modality, in sigma.
    async dailyDeviation(crimUserId, date) {
      return dailyDeviation(await store.onDay(Number(crimUserId), date));
    },

    // For the risk console. Includes the profile itself, so it is for admins only: shown to the
    // session it describes, it would tell an impostor exactly how to type.
    async report(crimUserId) {
      const profile = await profileFor(Number(crimUserId));
      const recent = await store.recent(Number(crimUserId), { limit: 30 });
      return {
        enrolment: enrolment(profile),
        profile: Object.entries(profile.modalities).flatMap(([modality, m]) => Object.entries(m.features).map(([key, f]) => ({
          modality, feature: key, label: FEATURE_BY_KEY[key].label, unit: FEATURE_BY_KEY[key].unit,
          median: round(f.median, 2), spread: round(f.scale, 2), windows: f.n,
        }))),
        recent: recent.map((w) => ({
          at: w.windowStart, keys: w.keystrokes, strokes: w.pointerStrokes, verdict: w.verdict, keysZ: round(w.keysZ, 2),
          pointerZ: round(w.pointerZ, 2), z: round(w.distanceZ, 2), trust: round(w.sessionTrust), decision: w.decision,
        })),
      };
    },

    async enrolmentFor(user) {
      return enrolment(await profileFor(await subjects.forUser(user)));
    },
  };
}

function createDisabled() {
  return {
    enabled: false,
    submit: async () => ({ verdict: 'enrolling', decision: 'ok', stepUp: false, frozen: false }),
    dailyDeviation: async () => ({ keys: null, pointer: null }),
    report: async () => null,
    enrolmentFor: async () => ({ enrolled: false, keys: false, pointer: false, needed: null }),
  };
}

module.exports = { createBiometrics };
