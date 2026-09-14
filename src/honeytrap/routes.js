'use strict';

// HTTP endpoints for dynamic honeytrapping. The paths a person's browser can see are named for
// what the decoys pretend to be - shared files - because anything called "honeytrap" in the
// page's network traffic would give the game away. Only the admin console uses the real name.
//
//   GET  /api/files/shared                registered by routes/files.js, which serves the real shares
//                                         and the decoys as one list, with the clipboard watch list
//   GET  /api/files/shared/:id            open one
//   POST /api/files/shared/integrity      { action, fingerprints } - clipboard matches from the page
//   GET  /api/internal/v1/...             trap endpoints: any canary presented as a credential trips
//   GET  /api/admin/honeytrap/people/:id  a person's plantings and trips (admins)
//   POST /api/admin/honeytrap/run         apply the policy to everyone now (admins)

const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson } = require('../http/response');

const ENDED = 'Your session has ended. Please sign in again.';

// Paths a leaked key would plausibly be tried against. They all answer like a real API that
// doesn't recognise the key.
const TRAP_PATHS = [
  '/api/internal/v1/credentials',
  '/api/internal/v1/exports',
  '/api/internal/v1/billing/customers',
  '/api/internal/v1/deploy',
];
const CREDENTIAL_HEADERS = ['authorization', 'x-api-key', 'x-auth-token', 'x-access-token', 'x-aws-access-key-id', 'x-amz-security-token'];

function credentialValues(req, url) {
  const values = [];
  for (const name of CREDENTIAL_HEADERS) {
    const header = req.headers[name];
    if (typeof header !== 'string') continue;
    values.push(header);
    const [scheme, rest] = header.split(/\s+/, 2);
    if (rest) values.push(rest);
    if (/^basic$/i.test(scheme) && rest) {
      const decoded = Buffer.from(rest, 'base64').toString('utf8');
      values.push(decoded, ...decoded.split(':'));
    }
  }
  for (const [, value] of url.searchParams) values.push(value);
  return values.slice(0, 40);
}

// The identity throttle has already frozen everyone a trip involves and ended their sessions;
// this only says whether the person making the request is one of them.
const signedOutBy = (reports, user) => Boolean(user) && reports.some((report) => report.redUserIds.includes(user.id));

function registerHoneytrapRoutes(router, { sessions, crimguard, honeytrap }) {
  // GET /api/files/shared belongs to routes/files.js: the decoys have to arrive in the same list
  // as the real shares, and only that route can see both.

  router.get('/api/files/shared/:id', async ({ req, res, params: { id }, client }) => {
    const user = sessions.requireUser(req);
    const opened = await honeytrap.openFile({ user, fileId: id, client });
    if (!opened) throw new HttpError(404, 'File not found.');
    if (opened.tripped) throw new HttpError(401, ENDED);
    sendJson(res, 200, { file: opened.file });
  });

  router.post('/api/files/shared/integrity', async ({ req, res, client }) => {
    const user = sessions.requireUser(req);
    const body = await readJson(req);
    const reports = await honeytrap.sighting({ user, action: body.action, fingerprints: body.fingerprints, client });
    if (signedOutBy(reports, user)) throw new HttpError(401, ENDED);
    sendJson(res, 202, { ok: true });
  });

  // No session required: a leaked key is usually tried from somewhere else entirely.
  const trap = async ({ req, res, url, client }) => {
    const user = sessions.current(req);
    await honeytrap.presentedCredentials({ values: credentialValues(req, url), via: `api:${url.pathname}`, user, client });
    sendJson(res, 401, { error: 'Invalid credentials.' }, { 'WWW-Authenticate': 'Bearer realm="internal"' });
  };
  for (const path of TRAP_PATHS) router.get(path, trap);

  router.get('/api/admin/honeytrap/people/:id', async ({ req, res, params: { id } }) => {
    sessions.requireAdmin(req);
    if (!crimguard) throw new HttpError(503, 'The risk database is not connected.');
    sendJson(res, 200, await honeytrap.report(id));
  });

  router.post('/api/admin/honeytrap/run', async ({ req, res }) => {
    sessions.requireAdmin(req);
    if (!crimguard) throw new HttpError(503, 'The risk database is not connected.');
    const { results, ...summary } = await honeytrap.evaluateAll();
    sendJson(res, 200, { ...summary, results });
  });

  return honeytrap;
}

module.exports = { registerHoneytrapRoutes, signedOutBy, TRAP_PATHS, credentialValues };
