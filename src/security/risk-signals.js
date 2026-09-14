'use strict';

// What raises and lowers an account's score besides the engine, and what a high score costs.
//
// The engine in crimguard/risk/ measures behaviour. Three things here sit beside that measurement
// rather than inside it, because none of them is behaviour:
//
//   email reputation  an address in a breach corpus, or a throwaway domain, is a fact about the
//                     account rather than something its owner did today.
//   MFA               proving who you are does not undo what the detectors saw, but it does answer
//                     the likeliest innocent explanation for a high score - somebody else is on
//                     this session - so it earns a bounded, expiring discount.
//   uploads           a high score narrows what an account can put *in*, not just what it can take
//                     out. Limiting already narrows reading (security/limits.js); this is the
//                     other direction.
//
// All of them are applied as signed deltas in risk_adjustments, never by editing the score:
// rewriting a measurement would falsify the record, and the next scoring run would overwrite it
// anyway. Effective score = engine score + Σ live deltas, clamped to 0-100.

const MIN_SCORE = 0;
const MAX_SCORE = 100;

// --- what each signal is worth -----------------------------------------------------------------

// Passing the step-up. Bounded and expiring: it answers "is this the right person", which is worth
// something, but an account that is exfiltrating does not stop being one because its owner can read
// an OTP. It never takes an account below the medium band on its own.
const MFA = Object.freeze({
  // Demanded once the effective score has sat at or above this since sign-in...
  atScore: 85,
  // ...for this long. A high score the moment someone lands is usually yesterday's, and throwing a
  // challenge at the sign-in itself teaches people to type codes on reflex.
  dwellMs: 2 * 60 * 1000,
  discount: -25,
  // Long enough to finish a day's work, short enough that tomorrow is judged fresh.
  holdsForMs: 12 * 60 * 60 * 1000,
  maxAttempts: 5,
  // Stand-in for a real factor. Deliberately obvious, and refused outright in production so it
  // cannot be shipped by accident (see assertDemoOtpAllowed).
  demoCode: '123456',
});

// Email reputation. Small numbers on purpose: neither is evidence of wrongdoing, and the engine's
// own amplifier rules apply here too - a stressor raises existing risk, it does not invent it.
const EMAIL = Object.freeze({
  breached: 8,
  // Many breaches is a different fact from one, so it scales, gently, to a cap.
  breachedPerExtra: 2,
  breachedMax: 18,
  disposable: 12,
  invalid: 6,
  blocked: 6,
  holdsForMs: 30 * 24 * 60 * 60 * 1000,
});

// Uploading. An account the detectors have flagged should not be adding to the pile it might be
// taking; the threshold is the one limiting already uses, so a person meets one rule, not two.
const UPLOAD_BLOCK_SCORE = 75;

// --- the effective score -----------------------------------------------------------------------

const clamp = (score) => Math.min(MAX_SCORE, Math.max(MIN_SCORE, score));

// SQL for the same sum, so db/files.js can reach it from inside the visibility query. Kept here
// beside the rule it implements; `u` is the users row in that query.
const LIVE_DELTA_SQL = `COALESCE((SELECT SUM(a.delta) FROM risk_adjustments a
  WHERE a.user_id = u.id AND (a.expires_at IS NULL OR a.expires_at > datetime('now'))), 0)`;

// base is the engine's score (or null when nobody has been scored yet). Adjustments on an unscored
// account do nothing: there is no measurement for them to move.
function effectiveScore(base, deltas = []) {
  if (base === null || base === undefined) return null;
  const total = deltas.reduce((sum, delta) => sum + Number(delta || 0), 0);
  return clamp(Number(base) + total);
}

const uploadBlocked = ({ score, exempt = false }) =>
  !exempt && Number.isFinite(score) && score >= UPLOAD_BLOCK_SCORE;

// --- the step-up -------------------------------------------------------------------------------

// Whether this session has to prove itself before it goes any further. `sessionAgeMs` is measured
// from sign-in, which is what makes this a dwell rather than a gate on the login itself.
function mfaRequired({ score, sessionAgeMs, passedAt = null, now = Date.now(), policy = MFA }) {
  if (passedAt && now - Date.parse(passedAt) < policy.holdsForMs) return false;
  if (!Number.isFinite(score) || score < policy.atScore) return false;
  return sessionAgeMs >= policy.dwellMs;
}

const otpValid = (code, policy = MFA) =>
  typeof code === 'string' && code.trim() === policy.demoCode;

// The demo OTP is a fixed string. That is fine for a demo and a hole in production, so production
// has to say out loud that it wants it.
function assertDemoOtpAllowed(env = process.env) {
  if (env.NODE_ENV === 'production' && env.RED_ALLOW_DEMO_OTP !== '1') {
    throw new Error(
      'The step-up is still using the fixed demo code 123456. Wire up a real factor, or set '
      + 'RED_ALLOW_DEMO_OTP=1 to say you know this build accepts a code anyone can guess.',
    );
  }
}

// --- email reputation into a delta ---------------------------------------------------------------

// One adjustment per finding, so the risk panel can say which fact cost what rather than showing a
// single number nobody can take apart.
function emailAdjustments(reputation, { policy = EMAIL } = {}) {
  if (!reputation) return [];
  const out = [];
  if (reputation.breached) {
    const extra = Math.max(0, Number(reputation.breachCount || 1) - 1);
    const delta = Math.min(policy.breachedMax, policy.breached + extra * policy.breachedPerExtra);
    out.push({
      kind: 'email_breached',
      delta,
      reason: `This address appears in ${reputation.breachCount === 1 ? 'a known breach' : `${reputation.breachCount} known breaches`}.`,
    });
  }
  if (reputation.disposable) {
    out.push({ kind: 'email_disposable', delta: policy.disposable, reason: 'A disposable or forwarding address.' });
  } else if (reputation.blocked) {
    out.push({ kind: 'email_blocked', delta: policy.blocked, reason: 'The domain is on the provider’s blocklist.' });
  }
  if (reputation.valid === false) {
    out.push({ kind: 'email_invalid', delta: policy.invalid, reason: 'The domain does not accept mail.' });
  }
  return out;
}

module.exports = {
  MIN_SCORE,
  MAX_SCORE,
  MFA,
  EMAIL,
  UPLOAD_BLOCK_SCORE,
  LIVE_DELTA_SQL,
  clamp,
  effectiveScore,
  uploadBlocked,
  mfaRequired,
  otpValid,
  assertDemoOtpAllowed,
  emailAdjustments,
};
