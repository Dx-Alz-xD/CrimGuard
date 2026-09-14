'use strict';

// Password hashing: HMAC-SHA-256 with a server-side pepper, then Argon2id.
//
//   stored = Argon2id( HMAC-SHA-256(pepper, NFKC(password)), random salt )
//
// Argon2id is the slow, memory-hard step that makes cracking a stolen hash expensive.
// The HMAC step mixes in a secret that lives outside the database (RED_PASSWORD_PEPPER),
// so a leaked database or backup on its own isn't enough to start guessing. It also turns
// any password into a fixed 32-byte input. SHA-256 on its own would be far too fast to
// protect passwords, which is why it's only ever used keyed, in front of Argon2id.
//
// Hashes use the standard PHC string format, which carries the parameters:
//   $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
// Raising the parameters later is safe: older hashes still verify and are rehashed on
// the next successful sign-in.

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const argon2 = promisify(crypto.argon2);
const scrypt = promisify(crypto.scrypt);

// RFC 9106 second recommended option: 64 MiB, 3 passes, 4 lanes. About 120 ms on a modern CPU.
const ARGON2_PARAMS = Object.freeze({ memory: 65536, passes: 3, parallelism: 4 });
const ARGON2_VERSION = 19; // 0x13
const SALT_BYTES = 16;
const TAG_BYTES = 32;

// Limits on parameters read back from the database, so a corrupted or tampered row can't
// make verification allocate gigabytes or spin for minutes.
const MAX_MEMORY_KIB = 1 << 20; // 1 GiB
const MAX_PASSES = 16;
const MAX_PARALLELISM = 16;

const b64 = (buffer) => buffer.toString('base64').replace(/=+$/, '');
const fromB64 = (text) => Buffer.from(text, 'base64');

function parseArgon2id(stored) {
  const match = /^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(stored);
  if (!match) return null;
  const [, version, memory, passes, parallelism, salt, hash] = match;
  const params = { version: Number(version), memory: Number(memory), passes: Number(passes), parallelism: Number(parallelism) };
  const saltBytes = fromB64(salt);
  const hashBytes = fromB64(hash);
  const sane = params.version === ARGON2_VERSION
    && params.memory >= 8 * params.parallelism && params.memory <= MAX_MEMORY_KIB
    && params.passes >= 1 && params.passes <= MAX_PASSES
    && params.parallelism >= 1 && params.parallelism <= MAX_PARALLELISM
    && saltBytes.length >= 8 && hashBytes.length >= 16 && hashBytes.length <= 64;
  return sane ? { ...params, salt: saltBytes, hash: hashBytes } : null;
}

// Hashes written by Red before Argon2id: scrypt$N$r$p$salt$key, with no pepper.
async function verifyLegacyScrypt(password, stored) {
  const [algorithm, n, r, p, salt, key, extra] = stored.split('$');
  if (algorithm !== 'scrypt' || !salt || !key || extra !== undefined) return false;
  const N = Number(n);
  const R = Number(r);
  const P = Number(p);
  if (![N, R, P].every(Number.isSafeInteger) || N > 1 << 20 || R > 32 || P > 16) return false;
  const expected = Buffer.from(key, 'base64');
  if (expected.length < 16) return false;
  const actual = await scrypt(password.normalize('NFKC'), Buffer.from(salt, 'base64'), expected.length, {
    N, r: R, p: P, maxmem: 256 * N * R + 1024 * 1024,
  });
  return crypto.timingSafeEqual(actual, expected);
}

function createPasswordHasher({ pepper }) {
  if (typeof pepper !== 'string' || Buffer.byteLength(pepper) < 32) {
    throw new Error('The password pepper must be at least 32 bytes.');
  }
  const pepperKey = Buffer.from(pepper, 'utf8');

  const prehash = (password) =>
    crypto.createHmac('sha256', pepperKey).update(password.normalize('NFKC'), 'utf8').digest();

  const derive = (password, salt, { memory, passes, parallelism }, tagLength) =>
    argon2('argon2id', { message: prehash(password), nonce: salt, memory, passes, parallelism, tagLength });

  async function hash(password) {
    if (typeof password !== 'string') throw new TypeError('password must be a string');
    const salt = crypto.randomBytes(SALT_BYTES);
    const tag = await derive(password, salt, ARGON2_PARAMS, TAG_BYTES);
    const { memory, passes, parallelism } = ARGON2_PARAMS;
    return `$argon2id$v=${ARGON2_VERSION}$m=${memory},t=${passes},p=${parallelism}$${b64(salt)}$${b64(tag)}`;
  }

  // Resolves to { valid, needsRehash }. needsRehash is true when the password was right but the
  // stored hash uses an older algorithm or weaker parameters, so the caller should store a fresh hash.
  async function verify(password, stored) {
    if (typeof password !== 'string' || typeof stored !== 'string') return { valid: false, needsRehash: false };

    if (stored.startsWith('scrypt$')) {
      const valid = await verifyLegacyScrypt(password, stored);
      return { valid, needsRehash: valid };
    }

    const parsed = parseArgon2id(stored);
    if (!parsed) return { valid: false, needsRehash: false };
    const actual = await derive(password, parsed.salt, parsed, parsed.hash.length);
    const valid = crypto.timingSafeEqual(actual, parsed.hash);
    const current = parsed.memory === ARGON2_PARAMS.memory
      && parsed.passes === ARGON2_PARAMS.passes
      && parsed.parallelism === ARGON2_PARAMS.parallelism
      && parsed.hash.length === TAG_BYTES;
    return { valid, needsRehash: valid && !current };
  }

  // Verified against when an email isn't registered, so a failed login does the same work,
  // and takes the same time, whether or not the account exists.
  let dummyHash;
  async function verifyDummy(password) {
    dummyHash ??= hash(crypto.randomBytes(32).toString('base64'));
    await verify(typeof password === 'string' ? password : '', await dummyHash);
    return { valid: false, needsRehash: false };
  }

  return { hash, verify, verifyDummy };
}

module.exports = { ARGON2_PARAMS, createPasswordHasher };
