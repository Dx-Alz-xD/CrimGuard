'use strict';

// The OTP step-up: what an account is asked for once its score has stayed high since it signed in.
//
//   GET  /api/me/step-up   whether this session owes one, and what it would be worth
//   POST /api/me/step-up   { code } - answers it
//
// The dwell is the point. A score is a judgement about a person's recent behaviour, and the moment
// they land it is usually yesterday's; challenging the sign-in itself teaches people to type codes
// on reflex, which is the habit phishing lives on. Waiting until the score has *stayed* high for a
// couple of minutes of this session means the challenge lands on the session it is actually about.
//
// Passing it earns a bounded, expiring discount rather than clearing the score, because proving who
// you are answers one innocent explanation for a high score - somebody else is on this session - and
// not the others. The rule and the numbers are in security/risk-signals.js.

const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson } = require('../http/response');
const { MFA, otpValid } = require('../security/risk-signals');
// The gate that holds a session until this is answered, and the paths it leaves open, are in
// security/session-gate.js alongside the identity throttle's password step-up.
const { otpStanding } = require('../security/session-gate');

function registerStepUpRoutes(router, { stores, sessions, telemetry, now = Date.now }) {
  const { signals, audit } = stores;

  router.get('/api/me/step-up', async ({ req, res }) => {
    const user = sessions.requireUser(req, { allowPasswordChange: true });
    const standing = otpStanding({ stores, user, tokenHash: req.sessionTokenHash, startedAt: req.sessionStartedAt, now: now() });
    sendJson(res, 200, {
      required: standing.required,
      passed: standing.passed,
      attempts: standing.attempts ?? 0,
      remaining: Math.max(0, MFA.maxAttempts - (standing.attempts ?? 0)),
      atScore: MFA.atScore,
      discount: Math.abs(MFA.discount),
    });
  });

  router.post('/api/me/step-up', async ({ req, res, client }) => {
    const user = sessions.requireUser(req, { allowPasswordChange: true });
    const tokenHash = req.sessionTokenHash;
    // Re-read rather than trust the caller: the demand has to exist before a code can answer it.
    otpStanding({ stores, user, tokenHash, startedAt: req.sessionStartedAt, now: now() });

    const body = await readJson(req);
    const code = typeof body.code === 'string' ? body.code : '';
    const result = signals.attempt({ tokenHash, correct: otpValid(code) });

    if (result.status === 'not_required') throw new HttpError(400, 'Nothing to confirm on this session.');
    if (result.status === 'already_passed') return sendJson(res, 200, { status: 'passed', discount: Math.abs(MFA.discount) });

    if (result.status === 'locked_out') {
      // Out of attempts. The session keeps its demand, so everything stays shut until an admin
      // looks - which is the right end state for an account that is high-risk *and* cannot
      // confirm who is on it.
      audit.record('security.step_up_locked', { actor: user, target: user, ...client, details: { attempts: result.attempts } });
      telemetry.onViolation({ user, tokenHash, client, path: '/api/me/step-up' });
      throw new HttpError(403, 'Too many wrong codes. This session is locked; ask an admin.', { code: 'step_up_locked' });
    }

    if (result.status === 'wrong') {
      audit.record('security.step_up_failed', { actor: user, target: user, ...client, details: { attempts: result.attempts } });
      throw Object.assign(new HttpError(400, 'That code is not right.', { code: 'step_up_failed' }), {
        details: { remaining: Math.max(0, MFA.maxAttempts - result.attempts) },
      });
    }

    // Passed. The discount is an adjustment beside the engine's score, never an edit to it, and it
    // expires on its own so tomorrow is judged fresh.
    signals.put(user.id, {
      delta: MFA.discount,
      kind: 'mfa_verified',
      reason: 'Confirmed it was them at the step-up.',
      detail: { scoreAt: result.scoreAt ?? null },
      expiresAt: new Date(now() + MFA.holdsForMs).toISOString(),
    });
    audit.record('security.step_up_passed', { actor: user, target: user, ...client, details: { scoreAt: result.scoreAt ?? null, discount: MFA.discount } });

    const state = stores.risk.state(user.id);
    sendJson(res, 200, {
      status: 'passed',
      discount: Math.abs(MFA.discount),
      score: state ? signals.effective(user.id, Number(state.score)) : null,
    });
  });
}

module.exports = { registerStepUpRoutes };
