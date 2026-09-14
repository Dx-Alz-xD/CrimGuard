'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

// Stored as scrypt$N$r$p$salt$key. Carrying the parameters in the string means
// they can be raised later without invalidating existing hashes.
const N = 16384;
const R = 8;
const P = 1;
const KEY_LENGTH = 64;

// Verified against when an email isn't registered, so a failed login takes the
// same time whether or not the account exists.
const DUMMY_HASH = ['scrypt', N, R, P, crypto.randomBytes(16).toString('base64'), crypto.randomBytes(KEY_LENGTH).toString('base64')].join('$');

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password.normalize('NFKC'), salt, KEY_LENGTH, { N, r: R, p: P });
  return ['scrypt', N, R, P, salt.toString('base64'), key.toString('base64')].join('$');
}

async function verifyPassword(password, stored) {
  const [algorithm, n, r, p, salt, key] = String(stored).split('$');
  if (algorithm !== 'scrypt' || !salt || !key) return false;
  const expected = Buffer.from(key, 'base64');
  const actual = await scrypt(password.normalize('NFKC'), Buffer.from(salt, 'base64'), expected.length, {
    N: Number(n),
    r: Number(r),
    p: Number(p),
  });
  return crypto.timingSafeEqual(actual, expected);
}

const newToken = () => crypto.randomBytes(32).toString('base64url');

// Only the hash of a session token is stored, so a leaked database can't be replayed as live sessions.
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

function parseCookies(header = '') {
  const cookies = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) cookies[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return cookies;
}

module.exports = { DUMMY_HASH, hashPassword, verifyPassword, newToken, hashToken, parseCookies };
