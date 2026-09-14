'use strict';

// The live console on the CrimGuard dashboard: the security activity log as it is written.
//
//   GET /api/admin/events            the latest events, oldest first
//   GET /api/admin/events?after=:id  anything newer than the last one the page has
//
// It reads, and only reads. The console's commands (filter, pause, clear...) run in the page and
// shape what is shown; nothing typed there reaches this server, because a shell on a dashboard
// that holds everyone's risk record would be the most valuable thing in Red to take over.
//
// It is the same log /api/admin/audit pages through, so it is shown to the same people. Reading it
// is worth recording for the same reason too - but a view that polls every few seconds is recorded
// once per viewer every ten minutes, not once per poll.

const { HttpError } = require('../http/errors');
const { sendJson } = require('../http/response');

const INITIAL = 100;
const MAX_BATCH = 200;
const RECORD_READ_EVERY_MS = 10 * 60 * 1000;

function registerEventRoutes(router, { stores, sessions, telemetry, now = Date.now }) {
  const lastRecorded = new Map(); // viewer id -> ms

  function recordRead({ req, client, viewer, count }) {
    const t = now();
    const last = lastRecorded.get(viewer.id);
    if (last !== undefined && t - last < RECORD_READ_EVERY_MS) return;
    lastRecorded.set(viewer.id, t);
    telemetry.onAccess({
      user: viewer, tokenHash: req.sessionTokenHash, client, kind: 'audit', name: 'Security activity log',
      action: 'read', batch: count,
    });
  }

  router.get('/api/admin/events', async ({ req, res, url, client }) => {
    const viewer = sessions.requireAdmin(req);
    const raw = url.searchParams.get('after');
    const after = raw === null || raw === '' ? null : Number(raw);
    if (after !== null && !(Number.isInteger(after) && after >= 0)) throw new HttpError(400, 'after must be an event id.');

    const events = stores.audit.tail({ after, limit: after === null ? INITIAL : MAX_BATCH });
    if (after === null || events.length) recordRead({ req, client, viewer, count: events.length });
    sendJson(res, 200, {
      events,
      // Where the next poll starts. Unchanged when nothing new arrived.
      cursor: events.length ? events.at(-1).id : after ?? 0,
      // A full batch means there may be more waiting; the page asks again straight away.
      more: after !== null && events.length === MAX_BATCH,
    });
  });
}

module.exports = { registerEventRoutes };
