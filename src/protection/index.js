'use strict';

// CrimGuard's active protection, wired together in one place:
//
//   identity    the dynamic identity throttle - step-up and freeze, from response policies on the
//               risk score and from everything below (src/identity/)
//   biometrics  keyboard and pointer dynamics against each owner's profile (src/biometrics/)
//   honeytrap   decoys planted for risky accounts, and the canaries that give a theft away
//               (src/honeytrap/)
//
// src/services.js builds this once, and the app calls into it at four points: routes, a
// per-request guard (by way of security/session-gate.js), the scoring hook, and saved text.
// Keeping every other detail here means the shared files change by a handful of lines when any
// of this does.

const { HttpError, sessionEnded } = require('../http/errors');
const { createSubjects } = require('../telemetry/subjects');
const { createIdentity } = require('../identity/identity');
const { registerIdentityRoutes } = require('../identity/routes');
const { createBiometrics } = require('../biometrics/biometrics');
const { registerBiometricRoutes } = require('../biometrics/routes');
const { createHoneytrap } = require('../honeytrap/honeytrap');
const { registerHoneytrapRoutes, signedOutBy } = require('../honeytrap/routes');

const HONEYTRAP_INTERVAL_MS = 60 * 60 * 1000;
const MAX_INSPECTED_BYTES = 2 * 1024 * 1024;

function createProtection({
  crimguard = null,
  stores,
  sessions,
  honeytrapInterval = HONEYTRAP_INTERVAL_MS,
  now = Date.now,
  log = console.warn,
  onError = (err) => console.error('CrimGuard protection:', err.message),
  honeytrapOptions = {},
} = {}) {
  const identity = createIdentity(crimguard, { stores, now, log });
  const biometrics = createBiometrics(crimguard, { identity, now });
  const honeytrap = createHoneytrap(crimguard, { identity, now, ...honeytrapOptions });
  const subjects = crimguard ? createSubjects(crimguard) : null;
  const stopHoneytrap = crimguard && honeytrapInterval > 0 ? honeytrap.schedule(honeytrapInterval, { onError }) : () => {};

  // Text someone is saving into Red: a canary in it trips the trap, and if that signs the author
  // out, the save is refused as a signed-out request.
  async function inspectText({ user, text, channel, client }) {
    if (!honeytrap.enabled || !text) return;
    const reports = await honeytrap.inspectText({ user, text, channel, client });
    if (signedOutBy(reports, user)) throw sessionEnded();
  }

  return {
    enabled: Boolean(crimguard),
    identity,
    biometrics,
    honeytrap,

    register(router, deps) {
      const all = { ...deps, identity, biometrics, honeytrap };
      registerIdentityRoutes(router, all);
      registerBiometricRoutes(router, all);
      registerHoneytrapRoutes(router, all);
    },

    // Before any API route runs, for a signed-in session on a path that is not left open while a
    // step-up is (security/session-gate.js decides both). A frozen account is signed out.
    async guard(req, user) {
      if (!identity.enabled) return;
      const status = await identity.statusFor(user, req.sessionTokenHash);
      if (status.frozen) {
        stores.sessions.removeAll(user.id);
        throw sessionEnded();
      }
      if (status.stepUp) {
        throw Object.assign(new HttpError(403, 'Please confirm it’s you to carry on.'), { code: 'step_up_required' });
      }
    },

    // Refuses a sign-in to an account that is frozen, before a session is made for it.
    async assertCanSignIn(redUserId) {
      if (await identity.isFrozenRedUser(redUserId)) {
        throw Object.assign(new HttpError(403, 'This account is locked pending a security review. Contact your administrator.'), { code: 'account_frozen' });
      }
    },

    inspectText,

    // An uploaded file, checked the same way when it is text. Binary files are skipped: a canary
    // pasted into a spreadsheet or archive is out of reach without parsing it.
    async inspectUpload({ user, content, client }) {
      if (!honeytrap.enabled || !content?.byteLength || content.byteLength > MAX_INSPECTED_BYTES) return;
      if (content.subarray(0, 8192).includes(0)) return;
      await inspectText({ user, text: content.toString('utf8'), channel: 'project_file', client });
    },

    // Called by telemetry right after a person's day is scored.
    async onScored({ crimUserId }) {
      try {
        await identity.evaluate(crimUserId);
        await honeytrap.evaluate(crimUserId);
      } catch (err) {
        onError(err);
      }
    },

    // A decoy project (src/telemetry/honeytokens.js) was touched. routes/projects.js and
    // routes/files.js have ended the sessions; the throttle makes it a freeze, so signing back in
    // waits for an admin.
    async onHoneytokenTrip(report) {
      if (!identity.enabled || !report?.user) return;
      try {
        await identity.respond({
          crimUserId: await subjects.forUser(report.user), action: 'session_freeze', source: 'decoy_project',
          reasons: [`${report.interaction} decoy "${report.decoy}"`],
        });
      } catch (err) {
        onError(err);
      }
    },

    close() {
      stopHoneytrap();
    },
  };
}

module.exports = { createProtection };
