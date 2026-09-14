'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { PASSWORD, startApp } = require('./helpers');

let app;
before(async () => { app = await startApp(); });
after(() => app.close());

test('only admins can list people, add people, assign roles, or read the activity log', async () => {
  const { b: userB, user } = await app.signUp('Pat');
  assert.equal((await userB('GET', '/api/admin/users')).status, 403);
  assert.equal((await userB('GET', '/api/admin/audit')).status, 403);
  assert.equal((await userB('PATCH', `/api/admin/users/${user.id}/role`, { role: 'admin' })).status, 403);
  assert.equal((await userB('POST', '/api/admin/users', { name: 'X', email: app.freshEmail(), password: PASSWORD, role: 'admin' })).status, 403);

  const admin = await app.signInAdmin();
  const list = await admin.b('GET', '/api/admin/users');
  assert.equal(list.status, 200);
  assert.ok(list.body.users.some((u) => u.id === user.id && u.role === 'user'));
  assert.ok(list.body.users.every((u) => !Object.keys(u).some((key) => key.includes('password'))));
});

test('a role change applies to sessions that are already signed in', async () => {
  const { b: patB, user } = await app.signUp('Promoted Pat');
  const admin = await app.signInAdmin();

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
  const admin = await app.signInAdmin();
  const { user } = await app.signUp();
  assert.equal((await admin.b('PATCH', `/api/admin/users/${admin.user.id}/role`, { role: 'user' })).status, 400);
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'owner' })).status, 400);
  assert.equal((await admin.b('PATCH', '/api/admin/users/999999/role', { role: 'admin' })).status, 404);
});

test('people added by an admin must choose their own password before doing anything else', async () => {
  const admin = await app.signInAdmin();
  const email = app.freshEmail();

  const created = await admin.b('POST', '/api/admin/users', { name: 'New Admin', email, password: PASSWORD, role: 'admin' });
  assert.equal(created.status, 201);
  assert.equal(created.body.user.role, 'admin');
  assert.equal(created.setCookie, null, 'adding someone must not switch the admin into their session');

  const newcomer = app.browser();
  const login = await newcomer('POST', '/api/login', { email, password: PASSWORD, portal: 'admin' });
  assert.equal(login.status, 200);
  assert.equal(login.body.mustChangePassword, true);
  assert.equal((await newcomer('GET', '/api/me')).body.user.mustChangePassword, true);

  const blocked = await newcomer('GET', '/api/admin/users');
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.code, 'password_change_required');
  assert.equal((await newcomer('GET', '/api/projects')).status, 403);

  assert.equal((await newcomer('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: 'my-own-secret-1' })).status, 200);
  assert.equal((await newcomer('GET', '/api/me')).body.user.mustChangePassword, false);
  assert.equal((await newcomer('GET', '/api/admin/users')).status, 200);

  assert.equal((await admin.b('POST', '/api/admin/users', { name: 'Again', email, password: PASSWORD, role: 'user' })).status, 409);
  assert.equal((await admin.b('POST', '/api/admin/users', { name: 'No role', email: app.freshEmail(), password: PASSWORD })).status, 400);
  assert.equal((await admin.b('POST', '/api/admin/users', { name: 'Weak', email: app.freshEmail(), password: 'short', role: 'user' })).status, 400);
});

test("admins can set anyone's password, which signs that person out everywhere", async () => {
  const { b: laptop, email, user } = await app.signUp('Sam');
  const phone = app.browser();
  assert.equal((await phone('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200);
  assert.equal((await laptop('PATCH', `/api/admin/users/${user.id}/password`, { password: 'self-serve-12' })).status, 403);

  const admin = await app.signInAdmin();
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/password`, { password: 'short' })).status, 400);
  assert.equal((await admin.b('PATCH', '/api/admin/users/999999/password', { password: 'long-enough-12' })).status, 404);
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/password`, { password: 'brand-new-pass' })).status, 200);

  assert.equal((await laptop('GET', '/api/me')).status, 401);
  assert.equal((await phone('GET', '/api/me')).status, 401);
  const b = app.browser();
  assert.equal((await b('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 401);
  const relogin = await b('POST', '/api/login', { email, password: 'brand-new-pass', portal: 'user' });
  assert.equal(relogin.status, 200);
  assert.equal(relogin.body.mustChangePassword, true, 'an admin-chosen password must be replaced');
});

test('admins changing their own password stay signed in here but are signed out elsewhere', async () => {
  // Uses a second admin so the shared ADMIN credentials stay valid for other tests.
  const email = app.freshEmail();
  const { b: ada } = await app.signInAdmin();
  assert.equal((await ada('POST', '/api/admin/users', { name: 'Second Admin', email, password: PASSWORD, role: 'admin' })).status, 201);

  const here = app.browser();
  const elsewhere = app.browser();
  const login = await here('POST', '/api/login', { email, password: PASSWORD, portal: 'admin' });
  assert.equal((await here('PATCH', '/api/me/password', { currentPassword: PASSWORD, newPassword: 'second-admin-pass' })).status, 200);
  assert.equal((await elsewhere('POST', '/api/login', { email, password: 'second-admin-pass', portal: 'admin' })).status, 200);

  assert.equal((await here('PATCH', `/api/admin/users/${login.body.user.id}/password`, { password: 'rotated-pass-14' })).status, 200);
  assert.equal((await here('GET', '/api/me')).status, 200);
  assert.equal((await here('GET', '/api/me')).body.user.mustChangePassword, false, 'choosing your own password is not forced to change');
  assert.equal((await elsewhere('GET', '/api/me')).status, 401);
});

test('admins can delete a person, along with their profile, projects and sessions', async () => {
  const { b: dana, email, user } = await app.signUp('Dana');
  assert.equal((await dana('POST', '/api/projects', { name: 'Doomed' })).status, 201);
  assert.equal((await dana('DELETE', `/api/admin/users/${user.id}`)).status, 403);

  const admin = await app.signInAdmin();
  assert.equal((await admin.b('DELETE', `/api/admin/users/${admin.user.id}`)).status, 400);
  assert.equal((await admin.b('DELETE', `/api/admin/users/${user.id}`)).status, 204);
  assert.equal((await admin.b('DELETE', `/api/admin/users/${user.id}`)).status, 404);

  assert.equal((await dana('GET', '/api/me')).status, 401);
  assert.equal((await app.browser()('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 401);
  assert.ok((await admin.b('GET', '/api/admin/users')).body.users.every((u) => u.id !== user.id));
  for (const table of ['projects WHERE owner_id', 'sessions WHERE user_id', 'user_profiles WHERE user_id', 'user_credentials WHERE user_id']) {
    assert.equal(app.db.prepare(`SELECT COUNT(*) AS n FROM ${table} = ?`).get(user.id).n, 0, table);
  }
});

test('security events are recorded in the activity log without secrets', async () => {
  const { email, user } = await app.signUp('Audited Avery');
  await app.browser()('POST', '/api/login', { email, password: 'wrong-password-99' });
  await app.browser()('POST', '/api/login', { email: 'ghost@red.test', password: 'wrong-password-99' });
  const admin = await app.signInAdmin();
  await admin.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'admin' });

  const { status, body } = await admin.b('GET', '/api/admin/audit?limit=20');
  assert.equal(status, 200);
  const mine = body.events.filter((event) => event.target_email === email);
  assert.deepEqual(new Set(mine.map((event) => event.action)), new Set(['account.signup', 'login.failed', 'admin.role_changed']));
  assert.deepEqual(mine.find((event) => event.action === 'admin.role_changed').details, { from: 'user', to: 'admin' });

  const everything = JSON.stringify(app.db.prepare('SELECT * FROM audit_log').all());
  assert.ok(!everything.includes('wrong-password-99'));
  assert.ok(!everything.includes('ghost@red.test'), 'unknown emails typed at login are not stored');
  assert.ok(!everything.includes(PASSWORD));
});
