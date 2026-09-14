'use strict';

// HTTP endpoints for the identity throttle.
//
//   GET   /api/identity/status                            { stepUp, frozen } for this session
//   POST  /api/identity/step-up                           { password } - confirms it's the owner
//   GET   /api/admin/identity                             accounts under a response, policies (admins)
//   PATCH /api/admin/identity/policies/:id                { isEnabled, minFinalScore, requiresApproval }
//   POST  /api/admin/identity/actions/:id/approve         carry out an action waiting for approval
//   POST  /api/admin/identity/actions/:id/decline
//   POST  /api/admin/identity/people/:id/restore          { note } - lift a freeze

const { HttpError, sessionEnded, riskDatabaseMissing } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson } = require('../http/response');

function registerIdentityRoutes(router, { sessions, stores, passwords, throttle, limits, crimguard, identity }) {
  function requireRisk(req) {
    const admin = sessions.requireAdmin(req);
    if (!crimguard) throw riskDatabaseMissing();
    return admin;
  }

  router.get('/api/identity/status', async ({ req, res }) => {
    const user = sessions.requireUser(req, { allowPasswordChange: true });
    sendJson(res, 200, await identity.statusFor(user, req.sessionTokenHash));
  });

  router.post('/api/identity/step-up', async ({ req, res, client }) => {
    const user = sessions.requireUser(req, { allowPasswordChange: true });
    const status = await identity.statusFor(user, req.sessionTokenHash);
    if (!status.stepUp) {
      sendJson(res, 200, { status: 'not_required' });
      return;
    }

    const key = `stepup:user:${user.id}`;
    const wait = throttle.retryAfter(key);
    if (wait) throw new HttpError(429, 'Too many attempts. Try again later.', { headers: { 'Retry-After': String(wait) } });

    const body = await readJson(req);
    const password = typeof body.password === 'string' ? body.password : '';
    const stored = stores.users.passwordHash(user.id);
    const passed = Boolean(stored) && (await passwords.verify(password, stored)).valid;
    if (!passed) throttle.fail(key, limits.passwordCheckPerUser);

    const outcome = await identity.stepUp({ user, tokenHash: req.sessionTokenHash, client, passed });
    if (outcome.status === 'frozen') throw sessionEnded();
    if (!passed) {
      throw Object.assign(new HttpError(400, 'That password is incorrect.'), { code: 'step_up_failed' });
    }
    throttle.reset(key);
    stores.audit.record('security.step_up_passed', { actor: user, target: user, ...client });
    sendJson(res, 200, { status: outcome.status });
  });

  router.get('/api/admin/identity', async ({ req, res }) => {
    requireRisk(req);
    sendJson(res, 200, await identity.overview());
  });

  router.patch('/api/admin/identity/policies/:id', async ({ req, res, params: { id }, client }) => {
    const admin = requireRisk(req);
    const body = await readJson(req);
    const patch = {};
    if (body.isEnabled !== undefined) {
      if (typeof body.isEnabled !== 'boolean') throw new HttpError(400, 'isEnabled must be true or false.');
      patch.isEnabled = body.isEnabled;
    }
    if (body.requiresApproval !== undefined) {
      if (typeof body.requiresApproval !== 'boolean') throw new HttpError(400, 'requiresApproval must be true or false.');
      patch.requiresApproval = body.requiresApproval;
    }
    if (body.minFinalScore !== undefined) {
      patch.minFinalScore = body.minFinalScore === null ? null : Number(body.minFinalScore);
    }
    let policy;
    try {
      policy = await identity.updatePolicy(id, patch);
    } catch (err) {
      if (err instanceof RangeError) throw new HttpError(400, err.message);
      throw err;
    }
    if (!policy) throw new HttpError(404, 'No such policy.');
    stores.audit.record('security.identity_policy_changed', { actor: admin, ...client, details: { policy: policy.name, ...patch } });
    sendJson(res, 200, { policy });
  });

  router.post('/api/admin/identity/actions/:id/approve', async ({ req, res, params: { id }, client }) => {
    const admin = requireRisk(req);
    const result = await identity.approve(id, admin);
    if (!result) throw new HttpError(404, 'Nothing is waiting for approval with that id.');
    stores.audit.record('security.identity_action_approved', { actor: admin, ...client, details: { action: result.action } });
    sendJson(res, 200, result);
  });

  router.post('/api/admin/identity/actions/:id/decline', async ({ req, res, params: { id }, client }) => {
    const admin = requireRisk(req);
    const result = await identity.decline(id, admin);
    if (!result) throw new HttpError(404, 'Nothing is waiting for approval with that id.');
    stores.audit.record('security.identity_action_declined', { actor: admin, ...client, details: { id: result.id } });
    sendJson(res, 200, result);
  });

  router.post('/api/admin/identity/people/:id/restore', async ({ req, res, params: { id }, client }) => {
    const admin = requireRisk(req);
    const { rows } = await crimguard.query('SELECT id, email FROM users WHERE id = ?', [id]);
    if (!rows.length) throw new HttpError(404, 'No risk record for that person.');
    const body = await readJson(req);
    const result = await identity.restore(id, admin, typeof body.note === 'string' ? body.note : '');
    stores.audit.record('security.identity_access_restored', { actor: admin, ...client, details: { email: rows[0].email, ...result } });
    sendJson(res, 200, result);
  });
}

module.exports = { registerIdentityRoutes };
