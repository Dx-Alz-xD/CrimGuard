'use strict';

// Where a request came from, and which origin it was addressed to.
//
// Both answers are read from headers a client controls, so each is believed only as far as it
// has to be: X-Forwarded-* only behind our own proxy (RED_TRUST_PROXY), and a Host header only
// once it looks like a host. Anything this server writes an absolute URL from - a sitemap, a
// canonical link - goes through publicOrigin, never straight from the header.

const { HttpError } = require('./errors');

// A DNS name or a bracketed IPv6 literal, with an optional port.
const HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*|\[[0-9a-f:.]+\])(?::\d{1,5})?$/i;

const firstForwarded = (value) => String(value || '').split(',')[0].trim();

const validHost = (host) => typeof host === 'string' && host.length <= 255 && HOST.test(host);

// The host the client addressed.
const requestHost = (req, { trustProxy = false } = {}) =>
  (trustProxy && firstForwarded(req.headers['x-forwarded-host'])) || req.headers.host || '';

// The origin to write absolute URLs against. A configured RED_PUBLIC_ORIGIN always wins; without
// one it is the origin this request was addressed to, or null when that is not a plausible host.
function publicOrigin(req, { trustProxy = false, configured = null } = {}) {
  if (configured) return configured;
  const host = requestHost(req, { trustProxy });
  if (!validHost(host)) return null;
  const forwardedProto = trustProxy && firstForwarded(req.headers['x-forwarded-proto']);
  const scheme = forwardedProto === 'https' || forwardedProto === 'http'
    ? forwardedProto
    : (req.socket?.encrypted ? 'https' : 'http');
  return `${scheme}://${host.toLowerCase()}`;
}

// State-changing API calls must come from our own pages.
//  - They must be JSON, or raw bytes for file uploads. A cross-site page can't send application/json or
//    application/octet-stream without a CORS preflight, which this server never grants.
//  - Browsers label requests with Sec-Fetch-Site; anything not same-origin is refused. Browsers too old
//    to send it are checked by comparing Origin with Host instead. Sec-Fetch-Site is preferred because
//    a reverse proxy that rewrites Host would make every same-origin request look cross-origin.
//  - Session cookies are SameSite=Strict on top of that.
function assertSameOrigin(req, { trustProxy = false, binary = false } = {}) {
  const site = req.headers['sec-fetch-site'];
  if (site) {
    if (site !== 'same-origin' && site !== 'none') throw new HttpError(403, 'Cross-site requests are not allowed.');
  } else if (req.headers.origin) {
    let originHost = null;
    try { originHost = new URL(req.headers.origin).host; } catch { /* "null" or malformed */ }
    if (!originHost || originHost !== requestHost(req, { trustProxy })) throw new HttpError(403, 'Cross-site requests are not allowed.');
  }
  const expected = binary ? 'application/octet-stream' : 'application/json';
  if (!String(req.headers['content-type']).startsWith(expected)) {
    throw new HttpError(415, binary ? 'Send the file as application/octet-stream.' : 'Requests must be sent as JSON.');
  }
}

// RED_PUBLIC_ORIGIN, checked: a bare http(s) origin, nothing after the host.
function parsePublicOrigin(value) {
  if (!value) return null;
  let url;
  try { url = new URL(value); } catch { return undefined; }
  if (!['http:', 'https:'].includes(url.protocol) || url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
    return undefined;
  }
  return url.origin;
}

module.exports = { validHost, requestHost, publicOrigin, assertSameOrigin, parsePublicOrigin };
