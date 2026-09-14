'use strict';

// Whether a signed-in session may go any further right now. Every API request passes through
// here once routing has found it (src/app.js).
//
// Three things can hold a session, checked strongest first:
//
//   a freeze             src/identity/ - every session ends, and signing in waits for an admin
//   a password step-up   src/identity/ - a score policy, or a change in typing, asks the owner
//                        to confirm with their password
//   an OTP step-up       security/risk-signals.js - a score that has *stayed* high since sign-in
//
// Both step-ups can be open at once: a score of 87 crosses the identity policy at 70 and the OTP
// threshold at 85. So every path that answers either of them stays open while either is. Two
// gates that each left only their own answer reachable would refuse each other's answers, and
// the session would have nothing left to do but sign out.

const { HttpError } = require('../http/errors');

const OPEN_DURING_STEP_UP = Object.freeze([
  // Who am I, and signing out.
  /^\/api\/me$/,
  /^\/api\/logout$/,
  // Answering either step-up.
  /^\/api\/me\/step-up$/,
  /^\/api\/identity\//,
  // Evidence keeps arriving while the question is open, or a stranger could stop the collector
  // simply by leaving the dialog unanswered.
  /^\/api\/telemetry$/,
  /^\/api\/biometrics\/windows$/,
  /^\/api\/files\/shared\/integrity$/,
]);

const openDuringStepUp = (pathname) => OPEN_DURING_STEP_UP.some((pattern) => pattern.test(pathname));

// This session's OTP standing: whether it owes a code, and at what effective score.
function otpStanding({ stores, user, tokenHash, startedAt, now = Date.now() }) {
  const state = stores.risk.state(user.id);
  if (!state) return { required: false, passed: false };
  const score = stores.signals.effective(user.id, Number(state.score));
  return {
    ...stores.signals.demand({
      userId: user.id,
      tokenHash,
      score,
      sessionAgeMs: Math.max(0, now - Number(startedAt || now)),
      now,
    }),
    score,
  };
}

function createSessionGate({ stores, sessions, protection, now = Date.now }) {
  return async function guard(req, pathname) {
    if (openDuringStepUp(pathname)) return;
    const user = sessions.current(req);
    if (!user) return;

    await protection.guard(req, user);

    const standing = otpStanding({ stores, user, tokenHash: req.sessionTokenHash, startedAt: req.sessionStartedAt, now: now() });
    if (standing.required) {
      throw Object.assign(new HttpError(403, 'Confirm it’s you to carry on.', { code: 'mfa_required' }), {
        details: { atScore: standing.score, lockedOut: Boolean(standing.lockedOut) },
      });
    }
  };
}

module.exports = { OPEN_DURING_STEP_UP, openDuringStepUp, otpStanding, createSessionGate };
