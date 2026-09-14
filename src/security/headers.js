'use strict';

// Sent on every response. Google Fonts serves the Archivo stylesheet and font files;
// everything else, scripts and API calls included, must come from this origin.
const CONTENT_SECURITY_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' https://fonts.googleapis.com",
  'font-src https://fonts.gstatic.com',
  "img-src 'self' data:",
  "connect-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
].join('; ');

const BASE_HEADERS = Object.freeze({
  'Content-Security-Policy': CONTENT_SECURITY_POLICY,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Origin-Agent-Cluster': '?1',
  'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
});

// Browsers ignore HSTS received over plain HTTP, so it's only sent on HTTPS responses.
const HSTS = 'max-age=31536000; includeSubDomains';

function applySecurityHeaders(res, { https }) {
  for (const [name, value] of Object.entries(BASE_HEADERS)) res.setHeader(name, value);
  if (https) res.setHeader('Strict-Transport-Security', HSTS);
}

module.exports = { applySecurityHeaders, CONTENT_SECURITY_POLICY };
