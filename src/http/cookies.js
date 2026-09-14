'use strict';

function parseCookies(header = '') {
  const cookies = {};
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    // First occurrence wins, so a cookie injected later in the header can't override ours.
    if (!Object.hasOwn(cookies, name)) cookies[name] = part.slice(eq + 1).trim();
  }
  return cookies;
}

function serializeCookie(name, value, { maxAge, secure }) {
  const attributes = [`${name}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${Math.max(0, Math.floor(maxAge))}`];
  if (secure) attributes.push('Secure');
  return attributes.join('; ');
}

module.exports = { parseCookies, serializeCookie };
