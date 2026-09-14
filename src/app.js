'use strict';

const http = require('node:http');
const { DEFAULT_MAX_FILE_BYTES, RATE_LIMITS, SESSION_POLICY } = require('./config');
const { createStores } = require('./db');
const { HttpError } = require('./http/errors');
const { isHttps, clientIp, userAgent } = require('./http/request');
const { sendJson } = require('./http/response');
const { createRouter } = require('./http/router');
const { applySecurityHeaders } = require('./security/headers');
const { createPasswordHasher } = require('./security/passwords');
const { createSessionManager } = require('./security/sessions');
const { createThrottle } = require('./security/throttle');
const { registerAuthRoutes } = require('./routes/auth');
const { registerProfileRoutes } = require('./routes/profile');
const { registerProjectRoutes } = require('./routes/projects');
const { registerFileRoutes } = require('./routes/files');
const { registerAdminRoutes } = require('./routes/admin');
const { createPageHandler } = require('./routes/pages');

const HOUSEKEEPING_INTERVAL_MS = 60 * 60 * 1000;

// State-changing API calls must come from our own pages.
//  - They must be JSON, or raw bytes for file uploads. A cross-site page can't send application/json or
//    application/octet-stream without a CORS preflight,
//    which this server never grants.
//  - Browsers label requests with Sec-Fetch-Site; anything not same-origin is refused. Browsers too old
//    to send it are checked by comparing Origin with Host instead. Sec-Fetch-Site is preferred because
//    a reverse proxy that rewrites Host would make every same-origin request look cross-origin.
//  - Session cookies are SameSite=Strict on top of that.
function assertSameOrigin(req, { trustProxy, binary = false }) {
  const site = req.headers['sec-fetch-site'];
  if (site) {
    if (site !== 'same-origin' && site !== 'none') throw new HttpError(403, 'Cross-site requests are not allowed.');
  } else if (req.headers.origin) {
    const { origin } = req.headers;
    const forwardedHost = trustProxy && String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
    const expectedHost = forwardedHost || req.headers.host;
    let originHost = null;
    try { originHost = new URL(origin).host; } catch { /* "null" or malformed */ }
    if (!originHost || originHost !== expectedHost) throw new HttpError(403, 'Cross-site requests are not allowed.');
  }
  const expected = binary ? 'application/octet-stream' : 'application/json';
  if (!String(req.headers['content-type']).startsWith(expected)) {
    throw new HttpError(415, binary ? 'Send the file as application/octet-stream.' : 'Requests must be sent as JSON.');
  }
}

function createApp({
  db,
  pepper,
  secureCookies = false,
  trustProxy = false,
  rateLimits = RATE_LIMITS,
  sessionPolicy = SESSION_POLICY,
  now = Date.now,
  maxFileBytes = DEFAULT_MAX_FILE_BYTES,
}) {
  const stores = createStores(db);
  const passwords = createPasswordHasher({ pepper });
  const throttle = createThrottle(db, { now });
  const sessions = createSessionManager({ sessions: stores.sessions, policy: sessionPolicy, secureCookies, now });
  const deps = { stores, sessions, passwords, throttle, limits: rateLimits, maxFileBytes };

  const router = createRouter();
  registerAuthRoutes(router, deps);
  registerProfileRoutes(router, deps);
  registerProjectRoutes(router, deps);
  registerFileRoutes(router, deps);
  registerAdminRoutes(router, deps);
  const handlePage = createPageHandler({ db, sessions });

  async function route(req, res) {
    applySecurityHeaders(res, { https: isHttps(req) });

    let url;
    try {
      url = new URL(req.url, 'http://red.local');
    } catch {
      throw new HttpError(400, 'Bad request.');
    }
    const pathname = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, '') : url.pathname;
    const { method } = req;

    if (!pathname.startsWith('/api/')) {
      if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'Method not allowed.', { headers: { Allow: 'GET, HEAD' } });
      return handlePage(req, res, pathname);
    }

    // Matched first only to know whether the route takes raw bytes; the same-origin checks still come before 404/405.
    const found = router.match(method === 'HEAD' ? 'GET' : method, pathname);
    if (method !== 'GET' && method !== 'HEAD') assertSameOrigin(req, { trustProxy, binary: found?.options?.body === 'binary' });
    if (!found) throw new HttpError(404, 'Not found.');
    if (found.allowed) throw new HttpError(405, 'Method not allowed.', { headers: { Allow: found.allowed.join(', ') } });

    const client = { ip: clientIp(req, { trustProxy }), userAgent: userAgent(req) };
    return found.handler({ req, res, url, params: found.params, client });
  }

  function housekeeping() {
    try {
      stores.sessions.purgeExpired(now());
      throttle.purge(Math.max(...Object.values(rateLimits).map((limit) => limit.windowMs)));
      stores.audit.purge();
    } catch (err) {
      console.error('Housekeeping failed:', err);
    }
  }

  const server = http.createServer((req, res) => {
    route(req, res).catch((err) => {
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) console.error(err);
      if (res.headersSent) return res.destroy();
      const body = { error: status === 500 ? 'Something went wrong.' : err.message };
      if (err.code && status !== 500) body.code = err.code;
      sendJson(res, status, body, status === 500 ? {} : err.headers);
    });
  });

  // Don't let slow or idle clients hold connections open indefinitely.
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;

  housekeeping();
  const timer = setInterval(housekeeping, HOUSEKEEPING_INTERVAL_MS);
  timer.unref();
  server.on('close', () => clearInterval(timer));

  return server;
}

module.exports = { createApp };
