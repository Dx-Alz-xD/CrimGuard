'use strict';

const { HttpError } = require('./errors');

const MAX_BODY_BYTES = 32 * 1024;

async function readJson(req) {
  const declared = Number(req.headers['content-length']);
  if (declared > MAX_BODY_BYTES) throw new HttpError(413, 'Request body is too large.');

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Request body is too large.');
    chunks.push(chunk);
  }
  if (size === 0) return {};

  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Request body is not valid JSON.');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'Expected a JSON object.');
  return body;
}

// Hosting platforms terminate TLS at a proxy and forward plain HTTP, so also honour
// X-Forwarded-Proto. A spoofed header can only add the Secure flag, which weakens nothing.
const isHttps = (req) =>
  Boolean(req.socket.encrypted) || String(req.headers['x-forwarded-proto']).split(',')[0].trim() === 'https';

// The client's address. X-Forwarded-For is only believed when RED_TRUST_PROXY is set, and then
// only its last entry: the one added by our own proxy. Earlier entries are whatever the client sent.
function clientIp(req, { trustProxy }) {
  if (trustProxy) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',').map((part) => part.trim()).filter(Boolean);
    if (forwarded.length) return forwarded.at(-1).slice(0, 64);
  }
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '').slice(0, 64);
}

const userAgent = (req) => String(req.headers['user-agent'] || '').slice(0, 255);

module.exports = { MAX_BODY_BYTES, readJson, isHttps, clientIp, userAgent };
