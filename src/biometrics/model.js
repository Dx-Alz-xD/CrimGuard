'use strict';

// Is this the account owner at the keyboard and mouse? Pure functions, no database.
//
//  1. Profile. For each modality (keys, pointer), from the owner's own accepted windows, each
//     feature gets a median and a robust spread (1.4826 × MAD), never below the feature's floor.
//  2. Distance. A new window is compared feature by feature with the scaled Manhattan distance,
//     mean(|x − median| / spread), the detector that did best in Killourhy & Maxion's keystroke
//     benchmark (2009). Each term is capped so one odd feature can't decide alone.
//  3. Calibration. The same distance is taken for every one of the owner's windows against a
//     profile built without it (leave-one-out). How far a new distance sits above that spread,
//     in robust standard deviations, is the modality's z - the per-feature z-score idea from the
//     pitch, made comparable between a steady typist and an erratic one.
//  4. Fusion. When both modalities are present their z's are combined with a weighted Stouffer
//     sum, Σ wᵢzᵢ / √Σ wᵢ², which keeps the owner's scale while two moderate deviations that agree
//     add up to a strong one.
//  5. Session trust. A single window can be off - a phone call, one hand on a coffee - so windows
//     feed a running trust level, and only a sustained drop asks the person to prove who they
//     are. A session that was plainly its owner and then abruptly isn't (a handed-over or
//     hijacked session) is flagged at once as a sudden change.

const { MODALITIES } = require('./features');

const MODEL = Object.freeze({
  minEnrollWindows: 8,
  minEnrollDays: 2,          // a profile from one sitting learns that sitting, not the person
  maxProfileWindows: 60,
  minFeatureSamples: 4,
  termCap: 6,
  modalities: Object.freeze({
    keys: Object.freeze({ minCompared: 5, weight: 1 }),
    pointer: Object.freeze({ minCompared: 4, weight: 0.8 }),
  }),
  // Calibrated on simulated typists and pointer users (test/biometric-simulation.js); the
  // population test in test/biometrics.test.js holds the resulting error rates.
  matchZ: 2.5,
  mismatchZ: 4,
  probabilityMidZ: 3.5,
  probabilitySlope: 1.2,
  distanceScaleFloor: 0.08,
  distanceScaleShare: 0.15,
  trustMemory: 0.5,          // trust = memory × trust + (1 − memory) × match probability
  watchBelow: 0.65,
  challengeBelow: 0.35,
  challengeAfterMismatches: 2,
  suddenChange: Object.freeze({ afterMatches: 2, minTrust: 0.8, minZ: 6 }),
});

const finite = (value) => typeof value === 'number' && Number.isFinite(value);

function median(values) {
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

function robust(values) {
  const m = median(values);
  const deviations = values.map((v) => Math.abs(v - m));
  const mad = median(deviations);
  const scale = mad > 0 ? 1.4826 * mad : 1.2533 * (deviations.reduce((a, b) => a + b, 0) / values.length);
  return { median: m, scale, n: values.length };
}

const presentIn = (features, x) => features.filter(({ key }) => finite(x?.[key])).length;

function featureProfile(windows, features, P) {
  const out = {};
  for (const { key, floor } of features) {
    const values = windows.map((w) => w.features[key]).filter(finite);
    if (values.length < P.minFeatureSamples) continue;
    const { median: m, scale, n } = robust(values);
    out[key] = { median: m, scale: Math.max(scale, floor), n };
  }
  return out;
}

function compare(profileFeatures, x, minCompared, P = MODEL) {
  const deviations = [];
  for (const [key, { median: m, scale }] of Object.entries(profileFeatures)) {
    const value = x[key];
    if (finite(value)) deviations.push({ key, z: (value - m) / scale });
  }
  deviations.sort((a, b) => Math.abs(b.z) - Math.abs(a.z));
  if (deviations.length < minCompared) return { distance: null, compared: deviations.length, deviations };
  const distance = deviations.reduce((sum, d) => sum + Math.min(Math.abs(d.z), P.termCap), 0) / deviations.length;
  return { distance, compared: deviations.length, deviations };
}

const dayOf = (at) => String(at).slice(0, 10);

function modalityProfile(name, windows, P) {
  const { features } = MODALITIES[name];
  const { minCompared } = P.modalities[name];
  const usable = windows.filter((w) => presentIn(features, w.features) >= minCompared).slice(-P.maxProfileWindows);
  const profileFeatures = featureProfile(usable, features, P);
  const days = new Set(usable.map((w) => dayOf(w.windowStart))).size;
  const enrolled = usable.length >= P.minEnrollWindows && days >= P.minEnrollDays && Object.keys(profileFeatures).length >= minCompared;

  let distance = null;
  if (enrolled) {
    const own = [];
    for (let i = 0; i < usable.length; i++) {
      const without = featureProfile(usable.filter((_, j) => j !== i), features, P);
      const { distance: d } = compare(without, usable[i].features, minCompared, P);
      if (finite(d)) own.push(d);
    }
    const r = robust(own);
    distance = { median: r.median, scale: Math.max(r.scale, P.distanceScaleFloor, P.distanceScaleShare * r.median), n: own.length };
  }
  return {
    enrolled,
    windows: usable.length,
    days,
    needed: { windows: Math.max(0, P.minEnrollWindows - usable.length), days: Math.max(0, P.minEnrollDays - days) },
    features: profileFeatures,
    distance,
  };
}

// windows: the owner's accepted windows, oldest first, each { windowStart, features }.
function buildProfile(windows, P = MODEL) {
  const modalities = Object.fromEntries(Object.keys(MODALITIES).map((name) => [name, modalityProfile(name, windows, P)]));
  const enrolled = Object.values(modalities).some((m) => m.enrolled);
  const best = Object.values(modalities).sort((a, b) => Number(b.enrolled) - Number(a.enrolled) || b.windows - a.windows)[0];
  return {
    enrolled,
    windows: windows.length,
    days: new Set(windows.map((w) => dayOf(w.windowStart))).size,
    needed: best.needed,
    modalities,
  };
}

// One window against the profile. verdict: enrolling | insufficient | match | uncertain | mismatch.
function verifyWindow(profile, x, P = MODEL) {
  const none = { distanceZ: null, matchProbability: null, zs: {}, deviations: [] };
  if (!profile || !profile.enrolled) return { verdict: 'enrolling', ...none };

  const zs = {};
  const deviations = [];
  let weighted = 0;
  let weights = 0;
  let comparable = false;
  for (const [name, modality] of Object.entries(profile.modalities)) {
    if (presentIn(MODALITIES[name].features, x) < P.modalities[name].minCompared) continue;
    comparable = true;
    if (!modality.enrolled) continue;
    const { distance, deviations: d } = compare(modality.features, x, P.modalities[name].minCompared, P);
    if (distance === null) continue;
    const z = (distance - modality.distance.median) / modality.distance.scale;
    const { weight } = P.modalities[name];
    zs[name] = z;
    weighted += weight * z;
    weights += weight * weight;
    deviations.push(...d.slice(0, 5).map((item) => ({ ...item, modality: name })));
  }
  if (!weights) return { verdict: comparable ? 'enrolling' : 'insufficient', ...none };

  const distanceZ = weighted / Math.sqrt(weights);
  const matchProbability = 1 / (1 + Math.exp(P.probabilitySlope * (distanceZ - P.probabilityMidZ)));
  const verdict = distanceZ <= P.matchZ ? 'match' : distanceZ > P.mismatchZ ? 'mismatch' : 'uncertain';
  deviations.sort((a, b) => Math.abs(b.z) - Math.abs(a.z));
  return { verdict, distanceZ, matchProbability, zs, deviations: deviations.slice(0, 5) };
}

const JUDGED = new Set(['match', 'uncertain', 'mismatch']);

// A session starts trusted: the person has just signed in. decision: ok | watch | challenge.
function nextSessionState(state, result, P = MODEL) {
  const current = { trust: 1, mismatches: 0, judged: 0, matchStreak: 0, ...state };
  if (!JUDGED.has(result.verdict)) return { ...current, suddenChange: false, decision: decide(current, P) };

  const trust = P.trustMemory * current.trust + (1 - P.trustMemory) * result.matchProbability;
  const mismatches = result.verdict === 'mismatch' ? current.mismatches + 1 : result.verdict === 'match' ? 0 : current.mismatches;
  const S = P.suddenChange;
  const suddenChange = result.verdict === 'mismatch' && result.distanceZ >= S.minZ
    && current.matchStreak >= S.afterMatches && current.trust >= S.minTrust;
  const next = {
    trust,
    mismatches,
    judged: current.judged + 1,
    matchStreak: result.verdict === 'match' ? current.matchStreak + 1 : 0,
  };
  return { ...next, suddenChange, decision: suddenChange ? 'challenge' : decide(next, P) };
}

function decide({ trust, mismatches }, P = MODEL) {
  if (trust < P.challengeBelow || mismatches >= P.challengeAfterMismatches) return 'challenge';
  return trust < P.watchBelow ? 'watch' : 'ok';
}

// A day's deviation per modality for the risk engine (sigma): the median window z, never below
// 0. keys feeds keystroke_cadence_deviation, pointer feeds mouse_velocity_deviation.
function dailyDeviation(results) {
  const of = (field) => {
    const zs = results.map((r) => r[field]).filter(finite);
    return zs.length ? Math.max(0, median(zs)) : null;
  };
  return { keys: of('keysZ'), pointer: of('pointerZ') };
}

module.exports = { MODEL, robust, buildProfile, verifyWindow, nextSessionState, dailyDeviation, compare };
