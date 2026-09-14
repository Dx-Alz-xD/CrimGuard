'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { FEATURE_KEYS, KEY_FEATURES, POINTER_FEATURES, MIN_KEYS } = require('../src/biometrics/features');
const { parseBiometricWindow } = require('../src/biometrics/ingest');
const { MODEL, buildProfile, verifyWindow, nextSessionState, dailyDeviation } = require('../src/biometrics/model');
const { createBiometrics } = require('../src/biometrics/biometrics');
const { connectCrimGuard } = require('../src/db/crimguard');
const { createSubjects } = require('../src/telemetry/subjects');
const { loadAggregator, makeTypist, makePerson, session, simulateWindow, typeWindow } = require('./biometric-simulation');
const { startApp, PASSWORD } = require('./helpers');

const Aggregator = loadAggregator();
const quiet = () => {};
const daysAgo = (n, hour = 10) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 11) + `${String(hour).padStart(2, '0')}:00:00.000Z`;
const BOTH = { keys: 140, strokes: 30 };

// Sixteen windows over two days: what a new person's first week of ordinary use produces.
function enrolmentWindows(person, mode = { keys: 140 }) {
  const windows = [];
  for (let s = 0; s < 4; s++) {
    const sitting = session(person, person.seed * 10 + s);
    for (let w = 0; w < 4; w++) {
      const summary = simulateWindow(sitting, Aggregator, mode);
      windows.push({ windowStart: daysAgo(s < 2 ? 3 : 2, 9 + w), features: summary.features, keys: summary.keys, strokes: summary.strokes, windowSeconds: 60 });
    }
  }
  return windows;
}

// --- the browser aggregator ----------------------------------------------------------------------

test('the aggregator reduces typing and pointer movement to the agreed features and nothing else', () => {
  const summary = simulateWindow(session(makePerson(1), 1), Aggregator, { keys: 200, strokes: 40 });
  assert.ok(summary.keys >= 190);
  assert.ok(summary.strokes >= 35);
  assert.deepEqual(Object.keys(summary.features).sort(), [...FEATURE_KEYS].sort(), 'same vector as the server expects');
  for (const [key, value] of Object.entries(summary.features)) {
    assert.ok(value === null || (typeof value === 'number' && Number.isFinite(value)), key);
  }
  assert.ok(summary.features.dwellL > 20 && summary.features.dwellL < 400);
  assert.ok(summary.features.pointerSpeed > 50 && summary.features.pointerSpeed < 5000);
  assert.ok(summary.features.pointerStraightness > 0.5 && summary.features.pointerStraightness <= 1);
  assert.ok(summary.features.clickHold > 30 && summary.features.clickHold < 300);

  const keysOnly = typeWindow(session(makeTypist(2), 2), Aggregator);
  assert.ok(POINTER_FEATURES.every(({ key }) => keysOnly.features[key] === null), 'no pointer features without pointer evidence');
  const pointerOnly = simulateWindow(session(makePerson(3), 3), Aggregator, { strokes: 30 });
  assert.ok(KEY_FEATURES.every(({ key }) => pointerOnly.features[key] === null), 'and no typing features without typing');
});

test('too little typing is not a window, and auto-repeat and modifiers are not keystrokes', () => {
  const a = Aggregator();
  for (let i = 0; i < MIN_KEYS - 1; i++) {
    a.keyDown('KeyA', i * 150);
    a.keyDown('KeyA', i * 150 + 30); // auto-repeat while held
    a.keyUp('KeyA', i * 150 + 80);
    a.keyDown('ControlLeft', i * 150 + 90);
    a.keyUp('ControlLeft', i * 150 + 95);
  }
  assert.equal(a.keys, MIN_KEYS - 1);
  assert.equal(a.summary(), null);
});

test('rollover is measured: pressing the next key before releasing the last', () => {
  const replay = (hold) => {
    const events = [];
    for (let i = 0; i < 60; i++) {
      const code = i % 2 ? 'KeyJ' : 'KeyF';
      events.push({ type: 'keyDown', code, t: i * 100 }, { type: 'keyUp', code, t: i * 100 + hold });
    }
    const a = Aggregator();
    for (const e of events.sort((x, y) => x.t - y.t)) a[e.type](e.code, e.t);
    return a.summary().features;
  };
  assert.ok(replay(140).rollover > 0.9, 'held past the next key');
  assert.equal(replay(60).rollover, 0);
});

test('pointer strokes are split at pauses and clicks, and a straight line reads as straight', () => {
  const a = Aggregator();
  let t = 0;
  for (let s = 0; s < 20; s++) {
    for (let k = 0; k <= 20; k++) a.pointerMove(100 + k * 10, 100 + s, t += 10);
    t += 200; // a pause ends the stroke
    a.pointerDown(t);
    a.pointerUp(t + 90);
    t += 400;
  }
  const f = a.summary().features;
  assert.equal(a.strokes, 20);
  assert.ok(f.pointerStraightness > 0.99, `straightness ${f.pointerStraightness}`);
  assert.ok(Math.abs(f.pointerSpeed - 1000) < 60, `200 px in 200 ms is 1000 px/s, got ${f.pointerSpeed}`);
  assert.equal(f.clickHold, 90);
});

test('the collector sends timings only, skips password fields, and is the page’s one input listener', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'static', 'biometrics.js'), 'utf8');
  const send = source.slice(source.indexOf('function send('), source.indexOf('setInterval('));
  for (const forbidden of ['event.key', 'event.code', 'clientX', 'clientY', '.value', 'innerText', 'textContent']) {
    assert.ok(!send.includes(forbidden), `send() must not reach for ${forbidden}`);
  }
  assert.match(source, /type\)\.toLowerCase\(\) === 'password'/);

  const telemetry = fs.readFileSync(path.join(__dirname, '..', 'public', 'static', 'telemetry.js'), 'utf8');
  assert.doesNotMatch(telemetry, /addEventListener\('(keydown|keyup|mousemove|pointermove)'/, 'telemetry.js takes typing and pointer timings from biometrics.js');
  assert.match(telemetry, /CrimGuardBiometrics/);
  for (const page of ['dashboard.html', 'admin.html', 'risk.html']) {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', page), 'utf8');
    assert.ok(html.indexOf('biometrics.js') !== -1 && html.indexOf('biometrics.js') < html.indexOf('telemetry.js'), `${page} loads biometrics.js before telemetry.js`);
  }
});

// --- validation ------------------------------------------------------------------------------------

test('a window is clamped, unknown fields dropped, and a modality without enough behind it is blanked', () => {
  const now = Date.parse('2026-09-14T12:00:00Z');
  const features = Object.fromEntries(FEATURE_KEYS.map((key) => [key, 100]));
  const parsed = parseBiometricWindow({
    at: '2030-01-01T00:00:00Z', seconds: 99999, keys: 120, strokes: 3,
    features: { ...features, rollover: 7, dwellL: -5, extra: 1 }, device: { fingerprint: 'x'.repeat(500) },
  }, { now });
  assert.equal(parsed.features.rollover, 1);
  assert.equal(parsed.features.dwellL, 0);
  assert.equal(parsed.features.extra, undefined);
  assert.equal(parsed.features.pointerSpeed, null, 'three strokes are not pointer evidence');
  assert.equal(parsed.strokes, 0);
  assert.equal(parsed.windowSeconds, 600);
  assert.equal(parsed.fingerprint.length, 128);
  assert.ok(Date.parse(parsed.windowStart) <= now + 5 * 60 * 1000, 'future timestamps are pulled back');

  assert.equal(parseBiometricWindow({ keys: 10, strokes: 2, features }), null);
  assert.equal(parseBiometricWindow({ keys: 100, features: { dwellL: 90, dwellR: 90 } }), null);
  assert.equal(parseBiometricWindow({ strokes: 30, features }).keys, 0, 'pointer alone is a window');
  assert.throws(() => parseBiometricWindow('nope'), (err) => err.status === 400);
  assert.throws(() => parseBiometricWindow({ keys: 100 }), (err) => err.status === 400);
});

// --- the model -----------------------------------------------------------------------------------

test('enrolment needs enough windows over more than one day, per modality', () => {
  const typist = makeTypist(5);
  const windows = enrolmentWindows(typist);
  assert.equal(buildProfile(windows.slice(0, 5)).enrolled, false);
  const sameDay = buildProfile(windows.map((w) => ({ ...w, windowStart: daysAgo(2) })));
  assert.equal(sameDay.enrolled, false);
  assert.equal(sameDay.needed.days, 1);
  const profile = buildProfile(windows);
  assert.deepEqual([profile.enrolled, profile.modalities.keys.enrolled, profile.modalities.pointer.enrolled], [true, true, false]);
  assert.equal(verifyWindow(buildProfile(windows.slice(0, 3)), windows[0].features).verdict, 'enrolling');
});

// Owners over six sittings each, and every other person trying each profile for four windows.
function population(mode, size = 16) {
  const people = Array.from({ length: size }, (_, i) => makePerson(3000 + i));
  const profiles = people.map((p) => buildProfile(enrolmentWindows(p, mode)));
  const run = (profile, sitting) => {
    let state = null;
    for (let w = 1; w <= 4; w++) {
      state = nextSessionState(state, verifyWindow(profile, simulateWindow(sitting, Aggregator, mode).features));
      if (state.decision === 'challenge') return w;
    }
    return null;
  };
  let owners = 0;
  let ownersChallenged = 0;
  let impostors = 0;
  const caughtBy = [0, 0, 0, 0, 0];
  people.forEach((owner, i) => {
    assert.equal(profiles[i].enrolled, true);
    for (let s = 0; s < 6; s++) {
      owners += 1;
      if (run(profiles[i], session(owner, owner.seed * 77 + s))) ownersChallenged += 1;
    }
    people.forEach((other, j) => {
      if (i === j) return;
      impostors += 1;
      caughtBy[run(profiles[i], session(other, other.seed * 91 + i)) ?? 0] += 1;
    });
  });
  const byWindow = (n) => caughtBy.slice(1, n + 1).reduce((a, b) => a + b, 0) / impostors;
  return { owners: ownersChallenged / owners, byWindow };
}

test('across a population, typing and pointer each catch impostors, and together they catch more with fewer false alarms', () => {
  const keys = population({ keys: 140 });
  const pointer = population({ strokes: 30 });
  const both = population(BOTH);
  const pct = (x) => `${(x * 100).toFixed(1)}%`;

  assert.ok(keys.owners <= 0.03, `typing: owners challenged in ${pct(keys.owners)} of sittings`);
  assert.ok(keys.byWindow(2) >= 0.88, `typing: impostors caught by window 2: ${pct(keys.byWindow(2))}`);
  assert.ok(pointer.owners <= 0.03, `pointer: owners challenged in ${pct(pointer.owners)}`);
  assert.ok(pointer.byWindow(4) >= 0.7, `pointer: impostors caught by window 4: ${pct(pointer.byWindow(4))}`);
  assert.ok(both.owners <= Math.min(keys.owners, pointer.owners), `both: owners challenged in ${pct(both.owners)}`);
  assert.ok(both.byWindow(2) >= 0.97, `both: impostors caught by window 2: ${pct(both.byWindow(2))}`);
  assert.ok(both.byWindow(2) > Math.max(keys.byWindow(2), pointer.byWindow(2)), 'fusion adds to either alone');
});

test('a session handed to someone else mid-way is challenged on the stranger’s first window', () => {
  const people = Array.from({ length: 16 }, (_, i) => makePerson(3000 + i));
  const profiles = people.map((p) => buildProfile(enrolmentWindows(p, BOTH)));
  let caughtFirst = 0;
  let ownerFalse = 0;
  people.forEach((owner, i) => {
    let state = null;
    const own = session(owner, owner.seed * 5 + 1);
    for (let w = 0; w < 3; w++) state = nextSessionState(state, verifyWindow(profiles[i], simulateWindow(own, Aggregator, BOTH).features));
    const stranger = people[(i + 1) % people.length];
    state = nextSessionState(state, verifyWindow(profiles[i], simulateWindow(session(stranger, stranger.seed * 9 + i), Aggregator, BOTH).features));
    if (state.decision === 'challenge' && state.suddenChange) caughtFirst += 1;

    let ownerState = null;
    const sitting = session(owner, owner.seed * 131);
    for (let w = 0; w < 8; w++) {
      ownerState = nextSessionState(ownerState, verifyWindow(profiles[i], simulateWindow(sitting, Aggregator, BOTH).features));
      if (ownerState.suddenChange) ownerFalse += 1;
    }
  });
  assert.ok(caughtFirst >= 12, `handed-over sessions caught at once: ${caughtFirst}/16`);
  assert.ok(ownerFalse <= 1, `owners flagged as a sudden change: ${ownerFalse}/16`);
});

test('one odd window only lowers trust; a sustained run of them challenges; the day deviation is per modality', () => {
  const match = { verdict: 'match', matchProbability: 0.95, distanceZ: 0.5 };
  const odd = { verdict: 'mismatch', matchProbability: 0.02, distanceZ: 4.5 };
  let state = nextSessionState(null, odd);
  assert.equal(state.decision, 'watch');
  state = nextSessionState(state, match);
  assert.equal(state.decision, 'ok');
  state = nextSessionState(nextSessionState(state, odd), odd);
  assert.equal(state.decision, 'challenge');
  assert.equal(nextSessionState(null, { verdict: 'enrolling' }).decision, 'ok', 'windows during enrolment judge nothing');
  assert.deepEqual(dailyDeviation([{ keysZ: 1, pointerZ: null }, { keysZ: 3, pointerZ: 2 }, { keysZ: -2, pointerZ: -1 }]), { keys: 1, pointer: 0.5 });
  assert.ok(MODEL.challengeAfterMismatches >= 2);
});

// --- end to end, in the real app -----------------------------------------------------------------

async function withBiometrics(t) {
  const crimguard = await connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });
  const app = await startApp({
    crimguard, riskInterval: 0, protectionOptions: { log: quiet, honeytrapInterval: 0, honeytrapOptions: { log: quiet } },
  });
  t.after(async () => {
    await app.server.telemetry.flush();
    app.close();
    await crimguard.close();
  });
  const { b, email, user } = await app.signUp('Olive Owner');
  await app.server.telemetry.flush();
  const { biometrics } = app.server.protection;
  const owner = makePerson(31);
  const crimId = await createSubjects(crimguard).forUser(user);
  for (const w of enrolmentWindows(owner, BOTH)) {
    await biometrics.submit({ user, tokenHash: null, window: { ...w, fingerprint: null } });
  }
  return { app, crimguard, b, email, user, owner, crimId, biometrics };
}

const post = (b, summary) => b('POST', '/api/biometrics/windows', {
  at: new Date().toISOString(), seconds: summary.seconds, keys: summary.keys, strokes: summary.strokes, features: summary.features,
});

async function setScore(crimguard, crimId, score, level, scenario = null) {
  const today = new Date().toISOString().slice(0, 10);
  const { rows } = await crimguard.query(
    'INSERT INTO risk_feature_snapshot (user_id, snapshot_date, period_start, period_end) VALUES (?, ?, ?, ?) RETURNING id',
    [crimId, today, `${today}T00:00:00.000Z`, `${today}T23:59:59.000Z`],
  );
  await crimguard.query('INSERT INTO risk_scores (snapshot_id, user_id, model_version, final_score, risk_level, scenario) VALUES (?, ?, ?, ?, ?, ?)',
    [rows[0].id, crimId, 'test', score, level, scenario]);
}

test('the owner carries on untouched, and the browser learns nothing about the score', async (t) => {
  const { b, crimguard, owner, biometrics, user } = await withBiometrics(t);
  assert.deepEqual((await biometrics.enrolmentFor(user)).enrolled, true);
  const sitting = session(owner, 999);
  for (let i = 0; i < 4; i++) {
    const res = await post(b, simulateWindow(sitting, Aggregator, BOTH));
    assert.equal(res.status, 202);
    assert.deepEqual(Object.keys(res.body).sort(), ['accepted', 'stepUp'], 'no score, distance or profile in the reply');
    assert.equal(res.body.stepUp, false);
  }
  const { rows } = await crimguard.query("SELECT verdict, keys_z, pointer_z FROM biometric_windows WHERE session_ref NOT LIKE 'red-user:%'");
  assert.equal(rows.length, 4);
  assert.ok(rows.filter((r) => r.verdict === 'match').length >= 3);
  assert.ok(rows.every((r) => Number.isFinite(r.keys_z) && Number.isFinite(r.pointer_z)), 'both modalities judged');
  assert.equal((await b('GET', '/api/projects')).status, 200);
});

test('someone else on the account gets a step-up for that session only, through the identity throttle', async (t) => {
  const { app, b, email, crimguard, crimId } = await withBiometrics(t);
  const phone = app.browser();
  assert.equal((await phone('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200);
  const impostor = session(makePerson(77), 5);

  let stepUp = false;
  for (let i = 0; i < 4 && !stepUp; i++) stepUp = (await post(b, simulateWindow(impostor, Aggregator, BOTH))).body.stepUp;
  assert.equal(stepUp, true, 'asked to confirm within four windows');

  const blocked = await b('GET', '/api/projects');
  assert.deepEqual([blocked.status, blocked.body.code], [403, 'step_up_required']);
  assert.equal((await phone('GET', '/api/projects')).status, 200, 'the owner’s other device is not the one that changed');
  assert.deepEqual((await b('GET', '/api/identity/status')).body, { frozen: false, stepUp: true });

  const { rows: actions } = await crimguard.query('SELECT action, status, request_payload FROM identity_actions WHERE user_id = ?', [crimId]);
  assert.equal(actions.length, 1);
  assert.deepEqual([actions[0].action, actions[0].status], ['step_up_mfa', 'sent']);
  assert.equal(actions[0].request_payload.source, 'biometrics');

  // Typing more "normally" can't clear it, and nothing typed now becomes part of the profile.
  await post(b, simulateWindow(impostor, Aggregator, BOTH));
  assert.equal((await b('GET', '/api/identity/status')).body.stepUp, true);

  assert.equal((await b('POST', '/api/identity/step-up', { password: 'not-the-password' })).status, 400);
  const right = await b('POST', '/api/identity/step-up', { password: PASSWORD });
  assert.deepEqual([right.status, right.body.status], [200, 'verified']);
  assert.equal((await b('GET', '/api/projects')).status, 200);

  const { rows: auth } = await crimguard.query("SELECT event_type FROM auth_events WHERE user_id = ? AND event_type LIKE 'mfa_%' ORDER BY id", [crimId]);
  assert.deepEqual(auth.map((r) => r.event_type), ['mfa_challenge', 'mfa_failure', 'mfa_success']);
  const { rows: learnt } = await crimguard.query("SELECT COUNT(*) AS n FROM biometric_windows WHERE verdict = 'match' AND session_ref NOT LIKE 'red-user:%'");
  assert.equal(Number(learnt[0].n), 0);
});

test('a stranger on an account whose score is already high is frozen, and signing in waits for an admin', async (t) => {
  const { app, b, email, crimguard, crimId } = await withBiometrics(t);
  await setScore(crimguard, crimId, 66, 'high', 'slow_exfiltration');
  const impostor = session(makePerson(79), 7);
  let status = 202;
  for (let i = 0; i < 4 && status === 202; i++) status = (await post(b, simulateWindow(impostor, Aggregator, BOTH))).status;
  assert.equal(status, 401);
  assert.equal((await b('GET', '/api/me')).status, 401);

  const login = await app.browser()('POST', '/api/login', { email, password: PASSWORD, portal: 'user' });
  assert.deepEqual([login.status, login.body.code], [403, 'account_frozen']);
  const { rows } = await crimguard.query("SELECT action, request_payload FROM identity_actions WHERE user_id = ? AND action = 'session_freeze'", [crimId]);
  assert.equal(rows.length, 1);
  assert.match(JSON.stringify(rows[0].request_payload.reasons), /biometric_mismatch_with_elevated_risk/);
});

test('typing drifting while the score is up asks for a step-up sooner than typing alone would', async (t) => {
  const { b, crimguard, crimId, owner } = await withBiometrics(t);
  await setScore(crimguard, crimId, 48, 'medium');
  // A borrowed laptop: the owner's pointer habits with a different typist's keyboard.
  const mixed = session({ seed: 400, typist: makeTypist(4242), mover: owner.mover }, 400);
  let decisions = [];
  for (let i = 0; i < 3; i++) {
    const res = await post(b, simulateWindow(mixed, Aggregator, BOTH));
    decisions.push(res.body.stepUp);
    if (res.body.stepUp) break;
  }
  const { rows } = await crimguard.query('SELECT request_payload FROM identity_actions WHERE user_id = ?', [crimId]);
  assert.ok(decisions.includes(true), `step-up raised: ${decisions}`);
  assert.ok(rows.some((r) => /biometric_(drift_with_risk_anomaly|mismatch|change_mid_session)/.test(JSON.stringify(r.request_payload.reasons))));
});

test('today’s biometric deviation feeds the risk engine, and only admins see a profile', async (t) => {
  const { app, b, crimguard, crimId, owner, biometrics } = await withBiometrics(t);
  const sitting = session(owner, 4242);
  for (let i = 0; i < 3; i++) await post(b, simulateWindow(sitting, Aggregator, BOTH));
  const today = new Date().toISOString().slice(0, 10);
  const deviation = await biometrics.dailyDeviation(crimId, today);
  assert.ok(Number.isFinite(deviation.keys) && deviation.keys < 3, `typing today: ${deviation.keys}σ`);
  assert.ok(Number.isFinite(deviation.pointer) && deviation.pointer < 3, `pointer today: ${deviation.pointer}σ`);

  await b('GET', '/api/projects');
  await app.server.telemetry.flush();
  await app.server.telemetry.runDay(today);
  const { rows } = await crimguard.query(
    `SELECT b.keystroke_cadence_deviation, b.mouse_velocity_deviation FROM feat_behavioral_biometrics b
     JOIN risk_feature_snapshot s ON s.id = b.snapshot_id WHERE s.user_id = ? AND s.snapshot_date = ?`, [crimId, today],
  );
  assert.equal(rows.length, 1);
  assert.ok(Math.abs(Number(rows[0].keystroke_cadence_deviation) - deviation.keys) < 1e-6, 'keystroke_cadence_deviation is the profile deviation');
  assert.ok(Math.abs(Number(rows[0].mouse_velocity_deviation) - deviation.pointer) < 1e-6, 'mouse_velocity_deviation likewise');

  assert.equal((await b('GET', `/api/admin/biometrics/people/${crimId}`)).status, 403);
  const admin = await app.signInAdmin();
  const report = await admin.b('GET', `/api/admin/biometrics/people/${crimId}`);
  assert.equal(report.status, 200);
  assert.deepEqual([report.body.enrolment.keys, report.body.enrolment.pointer], [true, true]);
  assert.ok(report.body.profile.some((f) => f.modality === 'pointer') && report.body.profile.some((f) => f.modality === 'keys'));
  assert.equal((await admin.b('GET', '/api/admin/biometrics/people/999999')).status, 404);
});

test('without the risk database the endpoint accepts and ignores windows', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  const { b } = await app.signUp('Nia');
  const res = await post(b, simulateWindow(session(makePerson(3), 3), Aggregator, BOTH));
  assert.deepEqual([res.status, res.body], [202, { accepted: false, stepUp: false }]);
  assert.equal(createBiometrics(null).enabled, false);
  assert.equal((await b('POST', '/api/biometrics/windows', { keys: 1 })).status, 400, 'still validated');
  assert.equal((await b('GET', '/api/projects')).status, 200);
});
