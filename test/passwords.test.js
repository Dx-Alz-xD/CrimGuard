'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createPasswordHasher } = require('../src/security/passwords');
const { checkPassword } = require('../src/security/password-policy');
const { PEPPER, passwords } = require('./helpers');

// The format Red stored before Argon2id, reproduced to test the upgrade path.
function legacyScryptHash(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password.normalize('NFKC'), salt, 64, { N: 16384, r: 8, p: 1 });
  return ['scrypt', 16384, 8, 1, salt.toString('base64'), key.toString('base64')].join('$');
}

test('hashes are Argon2id PHC strings with a unique salt', async () => {
  const a = await passwords.hash('correct horse battery');
  const b = await passwords.hash('correct horse battery');
  assert.match(a, /^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
  assert.notEqual(a, b);
});

test('verification accepts the right password and rejects others', async () => {
  const stored = await passwords.hash('correct horse battery');
  assert.deepEqual(await passwords.verify('correct horse battery', stored), { valid: true, needsRehash: false });
  assert.equal((await passwords.verify('correct horse batterY', stored)).valid, false);
  assert.equal((await passwords.verify('', stored)).valid, false);
});

test('the pepper is part of the hash: the same database row fails under a different pepper', async () => {
  const stored = await passwords.hash('correct horse battery');
  const other = createPasswordHasher({ pepper: 'a-completely-different-pepper-value-0123456789' });
  assert.equal((await other.verify('correct horse battery', stored)).valid, false);
});

test('passwords are Unicode-normalised before hashing', async () => {
  // "é" typed as one code point on one device and as "e" plus a combining accent on another.
  const stored = await passwords.hash('caf\u00e9 au lait please');
  assert.equal((await passwords.verify('cafe\u0301 au lait please', stored)).valid, true);
});

test('weaker parameters and legacy scrypt hashes verify, and ask to be rehashed', async () => {
  const scrypt = legacyScryptHash('an old password');
  assert.deepEqual(await passwords.verify('an old password', scrypt), { valid: true, needsRehash: true });
  assert.deepEqual(await passwords.verify('not the password', scrypt), { valid: false, needsRehash: false });

  const current = await passwords.hash('correct horse battery');
  const [, , , , salt] = current.split('$');
  const prehash = crypto.createHmac('sha256', PEPPER).update('correct horse battery').digest();
  const weakTag = crypto.argon2Sync('argon2id', { message: prehash, nonce: Buffer.from(salt, 'base64'), memory: 19456, passes: 2, parallelism: 1, tagLength: 32 });
  const weak = `$argon2id$v=19$m=19456,t=2,p=1$${salt}$${weakTag.toString('base64').replace(/=+$/, '')}`;
  assert.deepEqual(await passwords.verify('correct horse battery', weak), { valid: true, needsRehash: true });
});

test('malformed or hostile stored hashes are rejected without doing the work', async () => {
  for (const stored of ['', 'plain-text', '$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA',
    '$argon2id$v=19$m=99999999,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA', 'scrypt$99999999$8$1$c2FsdA==$a2V5']) {
    assert.deepEqual(await passwords.verify('whatever password', stored), { valid: false, needsRehash: false }, stored);
  }
});

test('a short pepper is refused', () => {
  assert.throws(() => createPasswordHasher({ pepper: 'too-short' }), /at least 32 bytes/);
});

test('the password policy wants length, not composition, and rejects the obvious', () => {
  assert.equal(checkPassword('purple monkey dishwasher'), null);
  assert.equal(checkPassword('tr0ub4dor&3x'), null);
  assert.match(checkPassword('short-one'), /12 to 256/);
  assert.match(checkPassword('x'.repeat(257)), /12 to 256/);
  assert.match(checkPassword('password1234'), /too easy/);
  assert.match(checkPassword('aaaaaaaaaaaaaaaa'), /too easy/);
  assert.match(checkPassword('abcdefghijklmnop'), /too easy/);
  assert.match(checkPassword('jordan.smith-2026!', { email: 'jordan.smith@red.test' }), /name or email/);
  assert.match(checkPassword('Jordan Smith Jr', { name: 'jordan smith jr' }), /name or email/);
});
