'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { ADMIN, PASSWORD, startApp } = require('./helpers');

let app;
before(async () => { app = await startApp(); });
after(() => app.close());

// --- sign-up and the two login portals ----------------------------------------

test('sign-up always creates an intern, even if the request asks for admin', async () => {
  const res = await app.browser()('POST', '/api/signup', { name: 'Sneaky', email: app.freshEmail(), password: PASSWORD, role: 'admin' });
  assert.equal(res.status, 201);
  assert.equal(res.body.user.role, 'intern');
  assert.equal(res.body.user.clearance, 1);
  assert.equal(res.body.redirect, '/dashboard');
});

test('sign-up validates input, enforces the password policy and rejects duplicate emails', async () => {
  const { email } = await app.signUp();
  const b = app.browser();
  const attempt = (body) => b('POST', '/api/signup', { name: 'Someone', email: app.freshEmail(), password: PASSWORD, ...body });
  assert.equal((await attempt({ email: email.toUpperCase() })).status, 409);
  assert.equal((await attempt({ password: 'short-pass' })).status, 400);
  assert.equal((await attempt({ password: 'password1234' })).status, 400);
  assert.equal((await attempt({ name: '  ' })).status, 400);
  assert.equal((await attempt({ name: '\u202E\u0007 ' })).status, 400, 'a name made only of control characters is empty');
  assert.equal((await attempt({ email: 'nope' })).status, 400);
});

test('passwords are stored as Argon2id hashes in their own table, never on the user row', async () => {
  const { user } = await app.signUp('Hash Check');
  const columns = app.db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
  assert.ok(!columns.some((name) => name.includes('password')));
  const { password_hash: stored } = app.db.prepare('SELECT password_hash FROM user_credentials WHERE user_id = ?').get(user.id);
  assert.match(stored, /^\$argon2id\$/);
  assert.ok(!stored.includes(PASSWORD));
});

test('users sign in through the user portal and are refused by the admin portal', async () => {
  const { email } = await app.signUp('Uma');
  const b = app.browser();

  const viaAdmin = await b('POST', '/api/login', { email, password: PASSWORD, portal: 'admin' });
  assert.equal(viaAdmin.status, 403);
  assert.equal(viaAdmin.setCookie, null);

  const viaUser = await b('POST', '/api/login', { email, password: PASSWORD, portal: 'user' });
  assert.equal(viaUser.status, 200);
  assert.equal(viaUser.body.redirect, '/dashboard');
  assert.equal((await b('GET', '/api/me')).body.user.email, email);
});

test('admins sign in through the admin portal and are refused by the user portal', async () => {
  const b = app.browser();
  assert.equal((await b('POST', '/api/login', { email: ADMIN.email, password: ADMIN.password, portal: 'user' })).status, 403);

  const res = await b('POST', '/api/login', { email: ADMIN.email, password: ADMIN.password, portal: 'admin' });
  assert.equal(res.status, 200);
  assert.equal(res.body.user.role, 'admin');
  assert.equal(res.body.redirect, '/admin');
});

test('a wrong password and an unknown email get the same answer', async () => {
  const b = app.browser();
  const wrong = await b('POST', '/api/login', { email: ADMIN.email, password: 'wrong-password', portal: 'admin' });
  const unknown = await b('POST', '/api/login', { email: 'nobody@red.test', password: 'wrong-password', portal: 'admin' });
  assert.equal(wrong.status, 401);
  assert.deepEqual([unknown.status, unknown.body], [wrong.status, wrong.body]);
});

test('signing in issues a new session token rather than keeping one the browser already had', async () => {
  const { b, email } = await app.signUp();
  const before = b.getCookie();
  assert.equal((await b('POST', '/api/login', { email, password: PASSWORD })).status, 200);
  assert.notEqual(b.getCookie(), before);
  const replay = app.browser();
  replay.useCookie(before);
  assert.equal((await replay('GET', '/api/me')).status, 401, 'the old session was ended');
});

test('logging out revokes the session on the server, not just in the browser', async () => {
  const { b } = await app.signUp();
  const token = b.getCookie();
  const out = await b('POST', '/api/logout');
  assert.match(out.setCookie, /Max-Age=0/);

  b.useCookie(token); // replay the old cookie
  assert.equal((await b('GET', '/api/me')).status, 401);
});

test('only a hash of the session token is stored', async () => {
  const { b } = await app.signUp();
  const token = b.getCookie().split('=')[1];
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE token_hash = ?').get(hash).n, 1);
  assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE token_hash = ?').get(token).n, 0);
});

// --- your own password ---------------------------------------------------------------

test('anyone signed in can change their own password, which signs out their other devices', async () => {
  assert.equal((await app.browser()('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: 'anon-pass-12345' })).status, 401);

  const { b: laptop, email } = await app.signUp('Casey');
  const phone = app.browser();
  assert.equal((await phone('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200);

  assert.equal((await laptop('PATCH', '/api/me/password', { currentPassword: 'not-my-password', newPassword: 'casey-new-pass' })).status, 400);
  assert.equal((await laptop('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: 'short' })).status, 400);
  assert.equal((await laptop('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: PASSWORD })).status, 400);
  assert.equal((await phone('GET', '/api/me')).status, 200, 'failed attempts must not sign anyone out');

  const oldLaptopCookie = laptop.getCookie();
  const changed = await laptop('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: 'casey-new-pass' });
  assert.equal(changed.status, 200);
  assert.ok(changed.setCookie, 'this device gets a fresh session token');
  assert.equal((await laptop('GET', '/api/me')).status, 200);
  assert.equal((await phone('GET', '/api/me')).status, 401);
  const stale = app.browser();
  stale.useCookie(oldLaptopCookie);
  assert.equal((await stale('GET', '/api/me')).status, 401, 'the pre-change token no longer works');

  const b = app.browser();
  assert.equal((await b('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 401);
  assert.equal((await b('POST', '/api/login', { email, password: 'casey-new-pass', portal: 'user' })).status, 200);
});

// --- legacy hashes -------------------------------------------------------------------

test('an account with a legacy scrypt hash can sign in, and is upgraded to Argon2id', async () => {
  const { user, email } = await app.signUp('Legacy Lee');
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(PASSWORD, salt, 64, { N: 16384, r: 8, p: 1 });
  const legacy = ['scrypt', 16384, 8, 1, salt.toString('base64'), key.toString('base64')].join('$');
  app.db.prepare('UPDATE user_credentials SET password_hash = ? WHERE user_id = ?').run(legacy, user.id);

  assert.equal((await app.browser()('POST', '/api/login', { email, password: 'wrong-password-1' })).status, 401);
  const stillLegacy = app.db.prepare('SELECT password_hash FROM user_credentials WHERE user_id = ?').get(user.id).password_hash;
  assert.equal(stillLegacy, legacy, 'a failed attempt changes nothing');

  assert.equal((await app.browser()('POST', '/api/login', { email, password: PASSWORD })).status, 200);
  const upgraded = app.db.prepare('SELECT password_hash FROM user_credentials WHERE user_id = ?').get(user.id).password_hash;
  assert.match(upgraded, /^\$argon2id\$/);
  assert.equal((await app.browser()('POST', '/api/login', { email, password: PASSWORD })).status, 200);
});

// --- rate limits and session lifetimes ------------------------------------------------

test('repeated wrong passwords for one email are blocked for a while, then allowed again', async () => {
  let clock = Date.now();
  const limited = await startApp({
    now: () => clock,
    rateLimits: {
      loginPerEmail: { limit: 3, windowMs: 60_000, blockMs: 120_000 },
      loginPerIp: { limit: 100, windowMs: 60_000, blockMs: 60_000 },
      signupPerIp: { limit: 100, windowMs: 60_000, blockMs: 60_000 },
      passwordCheckPerUser: { limit: 3, windowMs: 60_000, blockMs: 60_000 },
    },
  });
  try {
    const { email } = await limited.signUp('Target');
    const b = limited.browser();
    for (let i = 0; i < 3; i++) {
      assert.equal((await b('POST', '/api/login', { email, password: `wrong-guess-${i}` })).status, 401);
    }
    const blocked = await b('POST', '/api/login', { email, password: PASSWORD });
    assert.equal(blocked.status, 429, 'even the right password waits out the block');
    assert.equal(blocked.headers.get('retry-after'), '120');
    assert.equal((await b('POST', '/api/login', { email: 'unknown-person@red.test', password: 'wrong-guess-x' })).status, 401, 'other emails are unaffected');

    clock += 121_000;
    assert.equal((await b('POST', '/api/login', { email, password: PASSWORD })).status, 200);
  } finally {
    limited.close();
  }
});

test('sign-ups from one address are limited', async () => {
  const limited = await startApp({
    rateLimits: {
      loginPerEmail: { limit: 100, windowMs: 60_000, blockMs: 60_000 },
      loginPerIp: { limit: 100, windowMs: 60_000, blockMs: 60_000 },
      signupPerIp: { limit: 2, windowMs: 60_000, blockMs: 60_000 },
      passwordCheckPerUser: { limit: 3, windowMs: 60_000, blockMs: 60_000 },
    },
  });
  try {
    await limited.signUp();
    await limited.signUp();
    const third = await limited.browser()('POST', '/api/signup', { name: 'Third', email: limited.freshEmail(), password: PASSWORD });
    assert.equal(third.status, 429);
  } finally {
    limited.close();
  }
});

test('sessions end after the idle timeout, and admin sessions sooner than user sessions', async () => {
  let clock = Date.now();
  const timed = await startApp({
    now: () => clock,
    sessionPolicy: {
      user: { idleMs: 60 * 60_000, absoluteMs: 24 * 60 * 60_000 },
      admin: { idleMs: 10 * 60_000, absoluteMs: 60 * 60_000 },
      maxPerUser: 10,
    },
  });
  try {
    const { b: user } = await timed.signUp();
    const { b: admin } = await timed.signInAdmin();

    clock += 11 * 60_000;
    assert.equal((await user('GET', '/api/me')).status, 200);
    assert.equal((await admin('GET', '/api/me')).status, 401, 'admin idle timeout');

    // Activity every 50 minutes keeps a user session alive (11 + 28 × 50 min ≈ 23.5 h),
    // but not past its 24-hour absolute limit.
    for (let step = 0; step < 28; step++) {
      clock += 50 * 60_000;
      assert.equal((await user('GET', '/api/me')).status, 200, `step ${step}`);
    }
    clock += 50 * 60_000;
    assert.equal((await user('GET', '/api/me')).status, 401, 'absolute timeout');
  } finally {
    timed.close();
  }
});
