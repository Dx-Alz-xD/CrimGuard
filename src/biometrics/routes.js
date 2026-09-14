'use strict';

// HTTP endpoints for behavioural biometrics.
//
//   POST /api/biometrics/windows           one window of typing and pointer use from the signed-in page
//   GET  /api/admin/biometrics/people/:id  a person's profile and recent verdicts (admins)
//
// The session is the only thing that says whose window it is; nothing in the body does. The
// browser is told whether it must confirm who it is and nothing else - no score, no distance, no
// profile - so an impostor gets no feedback to tune against. Confirming happens through the
// identity throttle's step-up (src/identity/routes.js).

const { HttpError, sessionEnded, riskDatabaseMissing } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson } = require('../http/response');
const { parseBiometricWindow } = require('./ingest');

function registerBiometricRoutes(router, { sessions, crimguard, biometrics }) {
  router.post('/api/biometrics/windows', async ({ req, res }) => {
    const user = sessions.requireUser(req);
    const window = parseBiometricWindow(await readJson(req));
    if (!biometrics.enabled || !window) {
      sendJson(res, 202, { accepted: false, stepUp: false });
      return;
    }
    const result = await biometrics.submit({ user, tokenHash: req.sessionTokenHash, window });
    if (result.frozen) throw sessionEnded();
    sendJson(res, 202, { accepted: true, stepUp: result.stepUp });
  });

  router.get('/api/admin/biometrics/people/:id', async ({ req, res, params: { id } }) => {
    sessions.requireAdmin(req);
    if (!crimguard) throw riskDatabaseMissing();
    const { rows } = await crimguard.query('SELECT id FROM users WHERE id = ?', [id]);
    if (!rows.length) throw new HttpError(404, 'No risk record for that person.');
    sendJson(res, 200, await biometrics.report(id));
  });
}

module.exports = { registerBiometricRoutes };
