'use strict';

// The HTTP server: turns requests into route calls and errors into responses.
//
//   src/services.js           what a request can reach, and the hooks between those parts
//   src/routes/index.js       every API route
//   src/routes/pages.js       pages, static files and the crawl files
//   src/security/session-gate.js  whether a signed-in session may go any further right now
//   src/jobs.js               what runs on a timer

const http = require('node:http');
const { HttpError } = require('./http/errors');
const { assertSameOrigin } = require('./http/origin');
const { isHttps, clientIp, userAgent } = require('./http/request');
const { sendJson } = require('./http/response');
const { createRouter } = require('./http/router');
const { applySecurityHeaders } = require('./security/headers');
const { createSessionGate } = require('./security/session-gate');
const { createServices } = require('./services');
const { registerRoutes } = require('./routes');
const { createPageHandler } = require('./routes/pages');
const { RISK_INTERVAL_MS, startJobs } = require('./jobs');

function createApp(options) {
  const { trustProxy = false, publicOrigin = null, riskInterval = RISK_INTERVAL_MS } = options;
  const deps = createServices(options);
  const { sessions, telemetry, protection } = deps;

  const router = createRouter();
  registerRoutes(router, deps);
  const guard = createSessionGate(deps);
  const handlePage = createPageHandler({ ...deps, trustProxy, publicOrigin });

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

    const client = { ip: clientIp(req, { trustProxy }), userAgent: userAgent(req) };

    if (!pathname.startsWith('/api/')) {
      if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'Method not allowed.', { headers: { Allow: 'GET, HEAD' } });
      return handlePage(req, res, pathname, client);
    }

    // Matched first only to know whether the route takes raw bytes; the same-origin checks still come before 404/405.
    const found = router.match(method === 'HEAD' ? 'GET' : method, pathname);
    if (method !== 'GET' && method !== 'HEAD') assertSameOrigin(req, { trustProxy, binary: found?.options?.body === 'binary' });
    if (!found) throw new HttpError(404, 'Not found.');
    if (found.allowed) throw new HttpError(405, 'Method not allowed.', { headers: { Allow: found.allowed.join(', ') } });

    // Checked after routing so a 404 stays a 404.
    await guard(req, pathname);

    return found.handler({ req, res, url, params: found.params, client });
  }

  // A refusal is a risk signal in its own right: it is the only trace Red keeps of someone
  // reaching for something their role doesn't cover, and of a session cookie outliving its
  // session. Both are recorded here rather than in each route.
  function recordRefusal(req, status, client) {
    try {
      if (status === 403 && (req.url.startsWith('/api/admin/') || req.url.startsWith('/api/crimguard/'))) {
        const user = sessions.current(req);
        if (user) telemetry.onViolation({ user, tokenHash: req.sessionTokenHash, client, path: new URL(req.url, 'http://red.local').pathname });
      } else if (status === 401) {
        const stale = sessions.staleTokenHash(req);
        if (stale) telemetry.onStaleSession({ tokenHash: stale, client });
      }
    } catch { /* telemetry must never turn one failed request into two */ }
  }

  // Bytes served to a signed-in account, which is what bandwidth_usage_spike compares to a baseline.
  function countBytesServed(req, res) {
    let bytes = 0;
    const { write, end } = res;
    res.write = function countingWrite(chunk, ...rest) {
      if (chunk) bytes += Buffer.byteLength(chunk, typeof rest[0] === 'string' ? rest[0] : undefined);
      return write.call(this, chunk, ...rest);
    };
    res.end = function countingEnd(chunk, ...rest) {
      if (chunk && typeof chunk !== 'function') bytes += Buffer.byteLength(chunk, typeof rest[0] === 'string' ? rest[0] : undefined);
      return end.call(this, chunk, ...rest);
    };
    res.once('finish', () => {
      if (bytes > 0 && req.sessionUser) {
        telemetry.onBandwidth({ user: req.sessionUser, tokenHash: req.sessionTokenHash, client: { ip: clientIp(req, { trustProxy }) }, bytes });
      }
    });
  }

  const server = http.createServer((req, res) => {
    countBytesServed(req, res);
    route(req, res).catch((err) => {
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) console.error(err);
      recordRefusal(req, status, { ip: clientIp(req, { trustProxy }), userAgent: userAgent(req) });
      if (res.headersSent) return res.destroy();
      const body = { error: status === 500 ? 'Something went wrong.' : err.message };
      if (err.code && status !== 500) body.code = err.code;
      // Enough for the page to act on a refusal rather than dead-end on it - what the departure
      // gate is holding, and whether an ask for it is already in the queue.
      if (err.details && status !== 500) body.details = err.details;
      sendJson(res, status, body, status === 500 ? {} : err.headers);
    });
  });

  // Don't let slow or idle clients hold connections open indefinitely.
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;

  const jobs = startJobs({ ...deps, riskInterval });

  server.on('close', () => {
    jobs.stop();
    protection.close();
  });
  server.telemetry = telemetry;
  server.protection = protection;

  return server;
}

module.exports = { createApp };
