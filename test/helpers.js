'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { openDb, ensureAdmin } = require('../src/db');
const { createApp } = require('../src/app');

const ADMIN = { name: 'Ada Admin', email: 'ada@red.test', password: 'admin-pass-1' };
const PASSWORD = 'user-pass-1';

let db;
let server;
let base;

before(async () => {
  db = openDb(':memory:');
  await ensureAdmin(db, ADMIN);
  server = createApp({ db });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

// A simulated browser with its own cookie jar.
function browser() {
  let cookie = '';
  const call = async (method, url, body, headers = {}) => {
    const res = await fetch(base + url, {
      method,
      redirect: 'manual',
      headers: {
        ...(cookie ? { cookie } : {}),
        ...(method === 'GET' ? {} : { 'content-type': 'application/json' }),
        ...headers,
      },
      body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
    });
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    const isJson = (res.headers.get('content-type') || '').includes('application/json');
    return {
      status: res.status,
      location: res.headers.get('location'),
      setCookie,
      body: isJson ? await res.json() : await res.text(),
    };
  };
  call.getCookie = () => cookie;
  call.useCookie = (value) => { cookie = value; };
  return call;
}

let emailCounter = 0;
const freshEmail = () => `person${++emailCounter}@red.test`;

async function signUp(name = 'Test User') {
  const b = browser();
  const email = freshEmail();
  const res = await b('POST', '/api/signup', { name, email, password: PASSWORD });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return { b, email, user: res.body.user };
}

async function signInAdmin() {
  const b = browser();
  const res = await b('POST', '/api/login', { email: ADMIN.email, password: ADMIN.password, portal: 'admin' });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return { b, user: res.body.user };
}

// --- sign-up and the two login portals ----------------------------------------

test('sign-up always creates a plain user, even if the request asks for admin', async () => {
  const res = await browser()('POST', '/api/signup', { name: 'Sneaky', email: freshEmail(), password: PASSWORD, role: 'admin' });
  assert.equal(res.status, 201);
  assert.equal(res.body.user.role, 'user');
  assert.equal(res.body.redirect, '/dashboard');
});

test('sign-up validates input and rejects duplicate emails', async () => {
  const { email } = await signUp();
  const b = browser();
  assert.equal((await b('POST', '/api/signup', { name: 'Dup', email: email.toUpperCase(), password: PASSWORD })).status, 409);
  assert.equal((await b('POST', '/api/signup', { name: 'Short', email: freshEmail(), password: 'short' })).status, 400);
  assert.equal((await b('POST', '/api/signup', { name: '  ', email: freshEmail(), password: PASSWORD })).status, 400);
  assert.equal((await b('POST', '/api/signup', { name: 'Bad email', email: 'nope', password: PASSWORD })).status, 400);
});

test('users sign in through the user portal and are refused by the admin portal', async () => {
  const { email } = await signUp('Uma');
  const b = browser();

  const viaAdmin = await b('POST', '/api/login', { email, password: PASSWORD, portal: 'admin' });
  assert.equal(viaAdmin.status, 403);
  assert.equal(viaAdmin.setCookie, null);

  const viaUser = await b('POST', '/api/login', { email, password: PASSWORD, portal: 'user' });
  assert.equal(viaUser.status, 200);
  assert.equal(viaUser.body.redirect, '/dashboard');
  assert.equal((await b('GET', '/api/me')).body.user.email, email);
});

test('admins sign in through the admin portal and are refused by the user portal', async () => {
  const b = browser();
  assert.equal((await b('POST', '/api/login', { email: ADMIN.email, password: ADMIN.password, portal: 'user' })).status, 403);

  const res = await b('POST', '/api/login', { email: ADMIN.email, password: ADMIN.password, portal: 'admin' });
  assert.equal(res.status, 200);
  assert.equal(res.body.user.role, 'admin');
  assert.equal(res.body.redirect, '/admin');
});

test('a wrong password and an unknown email get the same answer', async () => {
  const b = browser();
  const wrong = await b('POST', '/api/login', { email: ADMIN.email, password: 'wrong-password', portal: 'admin' });
  const unknown = await b('POST', '/api/login', { email: 'nobody@red.test', password: 'wrong-password', portal: 'admin' });
  assert.equal(wrong.status, 401);
  assert.deepEqual([unknown.status, unknown.body], [wrong.status, wrong.body]);
});

test('logging out revokes the session on the server, not just in the browser', async () => {
  const { b } = await signUp();
  const token = b.getCookie();
  const out = await b('POST', '/api/logout');
  assert.match(out.setCookie, /Max-Age=0/);

  b.useCookie(token); // replay the old cookie
  assert.equal((await b('GET', '/api/me')).status, 401);
});

// --- projects ------------------------------------------------------------------

test('projects are private to the account that owns them, admins included', async () => {
  const alice = await signUp('Alice');
  const bob = await signUp('Bob');
  const created = await alice.b('POST', '/api/projects', { name: 'Secret plan', description: 'Step one', status: 'active' });
  assert.equal(created.status, 201);
  const { id } = created.body.project;

  assert.deepEqual((await bob.b('GET', '/api/projects')).body.projects, []);
  assert.equal((await bob.b('PATCH', `/api/projects/${id}`, { name: 'Hijacked' })).status, 404);
  assert.equal((await bob.b('DELETE', `/api/projects/${id}`)).status, 404);

  const admin = await signInAdmin();
  assert.equal((await admin.b('PATCH', `/api/projects/${id}`, { name: 'Hijacked' })).status, 404);

  const mine = (await alice.b('GET', '/api/projects')).body.projects;
  assert.equal(mine.length, 1);
  assert.equal(mine[0].name, 'Secret plan');
});

test('project updates are validated and deletes are permanent', async () => {
  const { b } = await signUp();
  const created = (await b('POST', '/api/projects', { name: '  Launch   site ' })).body.project;
  assert.equal(created.status, 'planning');

  const updated = await b('PATCH', `/api/projects/${created.id}`, { status: 'done' });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.project.name, 'Launch site');
  assert.equal(updated.body.project.status, 'done');

  assert.equal((await b('PATCH', `/api/projects/${created.id}`, { status: 'someday' })).status, 400);
  assert.equal((await b('PATCH', `/api/projects/${created.id}`, { name: '   ' })).status, 400);
  assert.equal((await b('DELETE', `/api/projects/${created.id}`)).status, 204);
  assert.equal((await b('DELETE', `/api/projects/${created.id}`)).status, 404);
});

// --- roles ---------------------------------------------------------------------

test('only admins can list people, add people, or assign roles', async () => {
  const { b: userB, user } = await signUp('Pat');
  assert.equal((await userB('GET', '/api/admin/users')).status, 403);
  assert.equal((await userB('PATCH', `/api/admin/users/${user.id}/role`, { role: 'admin' })).status, 403);
  assert.equal((await userB('POST', '/api/admin/users', { name: 'X', email: freshEmail(), password: PASSWORD, role: 'admin' })).status, 403);

  const admin = await signInAdmin();
  const list = await admin.b('GET', '/api/admin/users');
  assert.equal(list.status, 200);
  assert.ok(list.body.users.some((u) => u.id === user.id && u.role === 'user'));
  assert.ok(list.body.users.every((u) => !('password_hash' in u)));
});

test('a role change applies to sessions that are already signed in', async () => {
  const { b: patB, user } = await signUp('Promoted Pat');
  const admin = await signInAdmin();

  const promoted = await admin.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'admin' });
  assert.equal(promoted.status, 200);
  assert.equal(promoted.body.user.role, 'admin');
  assert.equal((await patB('GET', '/api/admin/users')).status, 200);
  assert.equal((await patB('GET', '/dashboard')).location, '/admin');

  await admin.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'user' });
  assert.equal((await patB('GET', '/api/admin/users')).status, 403);
  assert.equal((await patB('GET', '/admin')).location, '/dashboard');
});

test("admins can't change their own role, and roles are validated", async () => {
  const admin = await signInAdmin();
  const { user } = await signUp();
  assert.equal((await admin.b('PATCH', `/api/admin/users/${admin.user.id}/role`, { role: 'user' })).status, 400);
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'owner' })).status, 400);
  assert.equal((await admin.b('PATCH', '/api/admin/users/999999/role', { role: 'admin' })).status, 404);
});

test('admins can add a person with a role, who then signs in through the matching portal', async () => {
  const admin = await signInAdmin();
  const email = freshEmail();

  const created = await admin.b('POST', '/api/admin/users', { name: 'New Admin', email, password: PASSWORD, role: 'admin' });
  assert.equal(created.status, 201);
  assert.equal(created.body.user.role, 'admin');
  assert.equal(created.setCookie, null, 'adding someone must not switch the admin into their session');

  assert.equal((await browser()('POST', '/api/login', { email, password: PASSWORD, portal: 'admin' })).status, 200);
  assert.equal((await admin.b('POST', '/api/admin/users', { name: 'Again', email, password: PASSWORD, role: 'user' })).status, 409);
  assert.equal((await admin.b('POST', '/api/admin/users', { name: 'No role', email: freshEmail(), password: PASSWORD })).status, 400);
});

test("admins can set anyone's password, which signs that person out everywhere", async () => {
  const { b: laptop, email, user } = await signUp('Sam');
  const phone = browser();
  assert.equal((await phone('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200);
  assert.equal((await laptop('PATCH', `/api/admin/users/${user.id}/password`, { password: 'self-serve-1' })).status, 403);

  const admin = await signInAdmin();
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/password`, { password: 'short' })).status, 400);
  assert.equal((await admin.b('PATCH', '/api/admin/users/999999/password', { password: 'long-enough-1' })).status, 404);
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/password`, { password: 'brand-new-pass' })).status, 200);

  assert.equal((await laptop('GET', '/api/me')).status, 401);
  assert.equal((await phone('GET', '/api/me')).status, 401);
  const b = browser();
  assert.equal((await b('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 401);
  assert.equal((await b('POST', '/api/login', { email, password: 'brand-new-pass', portal: 'user' })).status, 200);
});

test('admins changing their own password stay signed in here but are signed out elsewhere', async () => {
  // Uses a second admin so the shared ADMIN credentials stay valid for other tests.
  const email = freshEmail();
  const { b: ada } = await signInAdmin();
  assert.equal((await ada('POST', '/api/admin/users', { name: 'Second Admin', email, password: PASSWORD, role: 'admin' })).status, 201);

  const here = browser();
  const elsewhere = browser();
  const login = await here('POST', '/api/login', { email, password: PASSWORD, portal: 'admin' });
  assert.equal((await elsewhere('POST', '/api/login', { email, password: PASSWORD, portal: 'admin' })).status, 200);

  assert.equal((await here('PATCH', `/api/admin/users/${login.body.user.id}/password`, { password: 'rotated-pass-1' })).status, 200);
  assert.equal((await here('GET', '/api/me')).status, 200);
  assert.equal((await elsewhere('GET', '/api/me')).status, 401);
});

test('admins can delete a person, along with their projects and sessions', async () => {
  const { b: dana, email, user } = await signUp('Dana');
  assert.equal((await dana('POST', '/api/projects', { name: 'Doomed' })).status, 201);
  assert.equal((await dana('DELETE', `/api/admin/users/${user.id}`)).status, 403);

  const admin = await signInAdmin();
  assert.equal((await admin.b('DELETE', `/api/admin/users/${admin.user.id}`)).status, 400);
  assert.equal((await admin.b('DELETE', `/api/admin/users/${user.id}`)).status, 204);
  assert.equal((await admin.b('DELETE', `/api/admin/users/${user.id}`)).status, 404);

  assert.equal((await dana('GET', '/api/me')).status, 401);
  assert.equal((await browser()('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 401);
  assert.ok((await admin.b('GET', '/api/admin/users')).body.users.every((u) => u.id !== user.id));
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM projects WHERE owner_id = ?').get(user.id).n, 0);
});

test('anyone signed in can change their own password, which signs out their other devices', async () => {
  assert.equal((await browser()('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: 'anon-pass-123' })).status, 401);

  const { b: laptop, email } = await signUp('Casey');
  const phone = browser();
  assert.equal((await phone('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200);

  assert.equal((await laptop('PATCH', '/api/me/password', { currentPassword: 'not-my-password', newPassword: 'casey-new-pass' })).status, 400);
  assert.equal((await laptop('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: 'short' })).status, 400);
  assert.equal((await laptop('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: PASSWORD })).status, 400);
  assert.equal((await phone('GET', '/api/me')).status, 200, 'failed attempts must not sign anyone out');

  assert.equal((await laptop('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: 'casey-new-pass' })).status, 200);
  assert.equal((await laptop('GET', '/api/me')).status, 200);
  assert.equal((await phone('GET', '/api/me')).status, 401);

  const b = browser();
  assert.equal((await b('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 401);
  assert.equal((await b('POST', '/api/login', { email, password: 'casey-new-pass', portal: 'user' })).status, 200);
});

// --- pages, security, deployment ------------------------------------------------

test('pages redirect based on session and role', async () => {
  const anon = browser();
  assert.equal((await anon('GET', '/dashboard')).location, '/login');
  assert.equal((await anon('GET', '/admin')).location, '/admin/login');
  assert.equal((await anon('GET', '/admin/login')).status, 200);
  assert.equal((await anon('GET', '/nope')).status, 404);

  const { b } = await signUp();
  assert.equal((await b('GET', '/dashboard')).status, 200);
  assert.equal((await b('GET', '/admin')).location, '/dashboard');
  assert.equal((await b('GET', '/login')).location, '/dashboard');

  const admin = await signInAdmin();
  assert.equal((await admin.b('GET', '/admin')).status, 200);
  assert.equal((await admin.b('GET', '/dashboard')).location, '/admin');
});

test('writes must be JSON, which blocks cross-site form posts', async () => {
  const { b } = await signUp();
  const res = await b('POST', '/api/projects', { name: 'x' }, { 'content-type': 'text/plain' });
  assert.equal(res.status, 415);
});

test('session cookies are HttpOnly and SameSite=Strict, and Secure behind an HTTPS proxy', async () => {
  const plain = await browser()('POST', '/api/signup', { name: 'Plain', email: freshEmail(), password: PASSWORD });
  assert.match(plain.setCookie, /HttpOnly/);
  assert.match(plain.setCookie, /SameSite=Strict/);
  assert.doesNotMatch(plain.setCookie, /Secure/);

  const proxied = await browser()('POST', '/api/signup', { name: 'Proxied', email: freshEmail(), password: PASSWORD }, { 'x-forwarded-proto': 'https' });
  assert.match(proxied.setCookie, /; Secure/);
});

test('health check responds and static files are served', async () => {
  const b = browser();
  const health = await b('GET', '/healthz');
  assert.equal(health.status, 200);
  assert.deepEqual(health.body, { ok: true });
  assert.equal((await b('GET', '/static/app.js')).status, 200);
});

test('static paths cannot escape the static folder', async () => {
  // fetch() would normalise "..", so send raw request paths.
  const statusFor = (rawPath) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: server.address().port, path: rawPath }, (res) => {
      res.resume();
      resolve(res.statusCode);
    }).on('error', reject);
  });
  assert.equal(await statusFor('/static/../../server.js'), 404);
  assert.equal(await statusFor('/static/..%2F..%2Fsrc%2Fapp.js'), 404);
});

test('in production, the first admin is never created with the default password', () => {
  const dbFile = path.join(os.tmpdir(), `red-test-${process.pid}-${Date.now()}.db`);
  try {
    const result = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js')], {
      env: { ...process.env, NODE_ENV: 'production', RED_DB: dbFile, RED_ADMIN_PASSWORD: '', HOST: '127.0.0.1', PORT: '0' },
      encoding: 'utf8',
      timeout: 15_000,
    });
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /RED_ADMIN_PASSWORD/);
  } finally {
    fs.rmSync(dbFile, { force: true });
  }
});
