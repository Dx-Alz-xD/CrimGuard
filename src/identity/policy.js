'use strict';

// What the identity throttle does, and when. Pure functions, no database.
//
// Two kinds of trigger feed it:
//
//  1. The risk score. response_policies holds the rules (07_detection_scoring.sql): a minimum
//     score, a scenario, or both, and the action to take. The defaults follow the pitch: a score
//     that crosses a threshold forces a step-up, a score too high freezes the account.
//
//  2. Behavioural biometrics. A change in how the keyboard and pointer are used is judged
//     together with the score, because the two mean different things alone and together:
//
//       typing changed, nothing else unusual          ask the person to confirm who they are
//       typing somewhat off, and the score is up      ask as well - an anomaly *alongside* a
//                                                     change in physical dynamics
//       typing changed, and the score is high         freeze - a stranger on an account that is
//                                                     already behaving badly is account compromise
//
// A freeze always outranks a step-up, and nothing is escalated twice for the same reason on the
// same day.

const DEFAULT_POLICIES = Object.freeze([
  Object.freeze({ name: 'Step-up at risk score 70', minFinalScore: 70, scenario: null, action: 'step_up_mfa' }),
  Object.freeze({ name: 'Freeze at risk score 90', minFinalScore: 90, scenario: null, action: 'session_freeze' }),
  Object.freeze({ name: 'Freeze on a honeytoken trip', minFinalScore: null, scenario: 'honeytoken_trip', action: 'session_freeze' }),
  Object.freeze({ name: 'Step-up on suspected credential compromise', minFinalScore: 50, scenario: 'credential_compromise', action: 'step_up_mfa' }),
]);

// The actions Red can carry out itself. The others in identity_action_type are recorded for an
// identity provider integration to pick up, and enforced here as the nearest equivalent.
const STRENGTH = Object.freeze({ step_up_mfa: 1, force_password_reset: 1, session_revoke: 2, session_freeze: 3, account_suspend: 3 });
const LOCKING = new Set(['session_freeze', 'account_suspend']);

// Biometric trust combined with the score. Levels are the engine's (60 = high).
const COMPOUND = Object.freeze({
  freezeChallengeFromScore: 60,
  stepUpWatchFromScore: 40,
});

const matches = (policy, risk) => {
  if (!policy.isEnabled || !risk) return false;
  if (policy.minFinalScore !== null && policy.minFinalScore !== undefined && !(risk.score >= policy.minFinalScore)) return false;
  if (policy.scenario && policy.scenario !== risk.scenario) return false;
  return policy.minFinalScore !== null || Boolean(policy.scenario);
};

// The strongest enabled policy the score triggers, or null.
function policyFor(risk, policies) {
  return policies.filter((policy) => matches(policy, risk))
    .sort((a, b) => (STRENGTH[b.action] ?? 0) - (STRENGTH[a.action] ?? 0)
      // A policy that named the scenario is the more specific of two equally strong ones.
      || Number(Boolean(b.scenario)) - Number(Boolean(a.scenario))
      || (b.minFinalScore ?? 0) - (a.minFinalScore ?? 0))[0] ?? null;
}

// What a biometric decision for a session calls for, given the latest risk score.
// decision: ok | watch | challenge (see src/biometrics/model.js).
function biometricAction({ decision, suddenChange = false }, risk, P = COMPOUND) {
  const score = risk?.score ?? 0;
  if (decision === 'challenge') {
    return score >= P.freezeChallengeFromScore
      ? { action: 'session_freeze', reason: 'biometric_mismatch_with_elevated_risk' }
      : { action: 'step_up_mfa', reason: suddenChange ? 'biometric_change_mid_session' : 'biometric_mismatch' };
  }
  if (decision === 'watch' && score >= P.stepUpWatchFromScore) {
    return { action: 'step_up_mfa', reason: 'biometric_drift_with_risk_anomaly' };
  }
  return null;
}

// Where an account stands, from its identity_actions rows (any order). ref is the session
// asking: a step-up raised by one session's typing applies to that session only.
function standing(actions, ref = null) {
  const sorted = [...actions].sort((a, b) => a.id - b.id);
  const restoredAt = Math.max(0, ...sorted.filter((a) => a.action === 'restore_access' && a.status === 'completed').map((a) => a.id));
  const live = sorted.filter((a) => a.id > restoredAt);
  const freeze = live.filter((a) => LOCKING.has(a.action) && a.status === 'completed').at(-1) ?? null;
  const stepUps = live.filter((a) => a.action === 'step_up_mfa' && a.status === 'sent'
    && (!a.payload?.sessionRef || a.payload.sessionRef === ref));
  const pending = live.filter((a) => a.status === 'pending');
  return { frozen: Boolean(freeze), freeze, stepUp: stepUps.length > 0, stepUps, pending };
}

module.exports = { DEFAULT_POLICIES, STRENGTH, LOCKING, COMPOUND, policyFor, biometricAction, standing };
