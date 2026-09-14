'use strict';

// A cost on every sign-in and sign-up attempt, paid by the browser before the password is looked at.
//
// What this is for, and what it is not. It does not tell a human from a machine, and nothing that
// fits in this file would: a model that can read a distorted-text image reads it better than the
// person it was meant to admit. What it does is make each attempt cost real CPU, which is the thing
// credential stuffing and sign-up floods actually depend on being free. Against one determined
// attacker it buys little; against the volume that makes those attacks worth running it is the
// difference between thousands of guesses a second and a few. Red's per-email and per-IP throttles
// (security/throttle.js) are still the rule that stops a targeted guesser; this thins what reaches
// them, and costs an honest person a few hundred milliseconds they never see.
//
// Why it is built here rather than pulled in. Red has no npm dependencies and serves
// `default-src 'none'`, so every hosted CAPTCHA would mean both a third-party script on the sign-in
// page and a hole in the CSP to let it run. The work is a few lines of SHA-256 either side.
//
// Stateless by design: the challenge carries its own expiry and difficulty, signed with a server
// secret, so nothing is stored until it is spent. Spent challenges are remembered only until they
// expire, which is what stops one solved puzzle being replayed for a whole run of guesses.

const crypto = require('node:crypto');

const VERSION = 'v1';
// ~16 bits is a few hundred ms of one core in a browser, and nothing to a person waiting on a form.
const BASE_DIFFICULTY = 16;
const MAX_DIFFICULTY = 22;
const TTL_MS = 5 * 60 * 1000;
// A solution is a decimal counter; this bounds what a malicious client can make us hash.
const MAX_SOLUTION_LENGTH = 24;

const sha256 = (value) => crypto.createHash('sha256').update(value).digest();

// How many leading zero bits a digest opens with.
function leadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) { bits += 8; continue; }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

const meets = (challenge, solution, difficulty) =>
  leadingZeroBits(sha256(`${challenge}:${solution}`)) >= difficulty;

function createProofOfWork({
  secret = crypto.randomBytes(32),
  baseDifficulty = BASE_DIFFICULTY,
  ttlMs = TTL_MS,
  now = Date.now,
} = {}) {
  // Challenges already spent, kept only as long as they could still be replayed. Red runs as a
  // single instance by design (see the README on scaling), so in-memory is the whole picture; a
  // multi-process deployment would need this in the database instead.
  const spent = new Map();

  const sign = (body) => crypto.createHmac('sha256', secret).update(body).digest('base64url');

  function purge() {
    const t = now();
    for (const [challenge, expiry] of spent) if (expiry <= t) spent.delete(challenge);
  }

  // Harder for a client that has been failing: an honest person pays the base cost, a run of
  // wrong passwords from one address pays more for each further try.
  const difficultyFor = (failures = 0) =>
    Math.min(MAX_DIFFICULTY, baseDifficulty + Math.min(6, Math.floor(failures / 2)));

  function issue({ failures = 0 } = {}) {
    const difficulty = difficultyFor(failures);
    const expiry = now() + ttlMs;
    const body = `${VERSION}.${crypto.randomBytes(16).toString('base64url')}.${expiry}.${difficulty}`;
    return { challenge: `${body}.${sign(body)}`, difficulty, expiresAt: new Date(expiry).toISOString() };
  }

  // Returns null when it is good, or a short reason the caller can pass on. Order matters: shape and
  // signature before anything derived from the contents.
  function check(challenge, solution) {
    if (typeof challenge !== 'string' || typeof solution !== 'string') return 'missing';
    if (challenge.length > 256 || solution.length > MAX_SOLUTION_LENGTH || !/^\d+$/.test(solution)) return 'malformed';

    const parts = challenge.split('.');
    if (parts.length !== 5 || parts[0] !== VERSION) return 'malformed';
    const [, , expiryText, difficultyText, mac] = parts;
    const body = parts.slice(0, 4).join('.');

    const expected = Buffer.from(sign(body));
    const given = Buffer.from(mac);
    if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return 'forged';

    const expiry = Number(expiryText);
    const difficulty = Number(difficultyText);
    if (!Number.isFinite(expiry) || !Number.isFinite(difficulty)) return 'malformed';
    if (expiry <= now()) return 'expired';
    if (spent.has(challenge)) return 'already_used';
    if (!meets(challenge, solution, difficulty)) return 'unsolved';

    // Spent only once it is known good, so a wrong guess cannot burn someone else's challenge.
    spent.set(challenge, expiry);
    if (spent.size > 10_000) purge();
    return null;
  }

  return { issue, check, purge, difficultyFor, get spentCount() { return spent.size; } };
}

// The same loop the browser runs, used by the tests and by anyone scripting against the API.
function solve(challenge, difficulty, { limit = 50_000_000 } = {}) {
  for (let n = 0; n < limit; n += 1) {
    if (meets(challenge, String(n), difficulty)) return String(n);
  }
  throw new Error('No solution found within the limit.');
}

module.exports = {
  VERSION, BASE_DIFFICULTY, MAX_DIFFICULTY, TTL_MS,
  leadingZeroBits, meets, createProofOfWork, solve,
};
