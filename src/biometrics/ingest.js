'use strict';

// Validates one biometrics window from public/static/biometrics.js.
//
// A page can post anything, so every feature is clamped to its range and anything unknown is
// dropped. A modality with too little behind it (fewer than 40 keys, fewer than 15 pointer
// strokes) or too few features to compare is blanked; a window left with neither is not an
// error - it is simply not evidence - and comes back as null.

const { HttpError } = require('../http/errors');
const { MODALITIES } = require('./features');

const MAX_KEYS = 5000;
const MAX_STROKES = 2000;
const MAX_SECONDS = 600;
const MIN_PRESENT = { keys: 6, pointer: 4 };
// Same clock rules as the telemetry batch: a window can't claim to be from tomorrow, or from so
// long ago that it would land on a day that has already been scored.
const MAX_AGE_MS = 6 * 60 * 60 * 1000;
const MAX_SKEW_MS = 5 * 60 * 1000;

function timestamp(value, now) {
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return new Date(now).toISOString();
  return new Date(Math.min(Math.max(ms, now - MAX_AGE_MS), now + MAX_SKEW_MS)).toISOString();
}

const count = (value, max) => {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.round(Math.min(n, max)) : 0;
};

function parseBiometricWindow(body, { now = Date.now() } = {}) {
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || !body.features || typeof body.features !== 'object' || Array.isArray(body.features)) {
    throw new HttpError(400, 'Expected a biometrics window.');
  }

  const evidence = { keys: count(body.keys, MAX_KEYS), strokes: count(body.strokes, MAX_STROKES) };
  const features = {};
  let usable = 0;
  for (const [name, { features: list, minEvidence, evidence: field }] of Object.entries(MODALITIES)) {
    const values = {};
    let present = 0;
    for (const { key, max } of list) {
      const raw = body.features[key];
      const n = raw === null || raw === undefined || raw === '' ? NaN : Number(raw);
      values[key] = Number.isFinite(n) ? Math.min(Math.max(n, 0), max) : null;
      if (values[key] !== null) present += 1;
    }
    const enough = evidence[field] >= minEvidence && present >= MIN_PRESENT[name];
    for (const key of Object.keys(values)) features[key] = enough ? values[key] : null;
    if (enough) usable += 1;
    else evidence[field] = 0;
  }
  if (!usable) return null;

  const fingerprint = body.device && typeof body.device.fingerprint === 'string' ? body.device.fingerprint.slice(0, 128) : null;
  return {
    windowStart: timestamp(body.at, now),
    windowSeconds: Math.round(Math.min(Math.max(Number(body.seconds) || 1, 1), MAX_SECONDS)),
    keys: evidence.keys,
    strokes: evidence.strokes,
    features,
    fingerprint,
  };
}

module.exports = { parseBiometricWindow, MIN_PRESENT };
