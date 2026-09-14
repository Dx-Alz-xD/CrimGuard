'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { CEO, PASSWORD, startApp } = require('./helpers');

let app;
before(async () => { app = await startApp(); });
after(() => app.close());

test('the built-in roles are intern, employee, admin and CEO, with rising clearance', async () => {
  const { b } = await app.signUp();
  const res = await b('GET', '/api/roles');
  assert.equal(res.status, 200);
  const builtIn = res.body.roles.filter((role) => role.built_in);
  assert.deepEqual(builtIn.map((role) => [role.name, role.label, role.clearance]), [
    ['intern', 'Intern', 1], ['employee', 'Employee', 2], ['admin', 'Admin', 4], ['ceo', 'CEO', 5],
  ]);
  assert.ok(res.body.roles.every((role) => !('member_count' in role)), 'how many people hold a role is for admins');

  const admin = await app.signInAdmin();
  assert.ok((await admin.b('GET', '/api/roles')).body.roles.every((role) => Number.isInteger(role.member_count)));
});

test('the CEO signs in through the admin console', async () => {
  const b = app.browser();
  assert.equal((await b('POST', '/api/login', { email: CEO.email, password: CEO.password, portal: 'user' })).status, 403);

  const res = await b('POST', '/api/login', { email: CEO.email, password: CEO.password, portal: 'admin' });
  assert.equal(res.status, 200);
  assert.equal(res.body.user.role, 'ceo');
  assert.equal(res.body.user.clearance, 5);
  assert.equal(res.body.redirect, '/admin');
  assert.equal((await b('GET', '/admin')).status, 200);
  assert.equal((await b('GET', '/dashboard')).location, '/admin');
  assert.equal((await b('GET', '/api/me')).body.user.clearance, 5);
});

test('only the CEO can create, change and delete roles', async () => {
  const admin = await app.signInAdmin();
  const ceo = await app.signInCeo();
  const { b: intern } = await app.signUp();

  const body = { label: 'Field sales', clearance: 3 };
  assert.equal((await intern('POST', '/api/admin/roles', body)).status, 403);
  assert.equal((await admin.b('POST', '/api/admin/roles', body)).status, 403);

  const created = await ceo.b('POST', '/api/admin/roles', body);
  assert.equal(created.status, 201, JSON.stringify(created.body));
  assert.deepEqual(
    [created.body.role.name, created.body.role.label, created.body.role.clearance, created.body.role.built_in],
    ['field_sales', 'Field sales', 3, false],
  );
  assert.equal((await ceo.b('POST', '/api/admin/roles', { label: 'FIELD SALES', clearance: 2 })).status, 409, 'labels are unique, ignoring case');
  assert.equal((await ceo.b('POST', '/api/admin/roles', { label: 'Too high', clearance: 6 })).status, 400);
  assert.equal((await ceo.b('POST', '/api/admin/roles', { label: 'Fractional', clearance: 2.5 })).status, 400);
  assert.equal((await ceo.b('POST', '/api/admin/roles', { label: '   ', clearance: 2 })).status, 400);

  const { id } = created.body.role;
  assert.equal((await admin.b('PATCH', `/api/admin/roles/${id}`, { clearance: 1 })).status, 403);
  const changed = await ceo.b('PATCH', `/api/admin/roles/${id}`, { label: 'Sales', clearance: 2 });
  assert.equal(changed.status, 200);
  assert.deepEqual([changed.body.role.name, changed.body.role.label, changed.body.role.clearance], ['field_sales', 'Sales', 2], 'the name stays put');

  const employee = (await ceo.b('GET', '/api/roles')).body.roles.find((role) => role.name === 'employee');
  assert.equal((await ceo.b('PATCH', `/api/admin/roles/${employee.id}`, { clearance: 3 })).status, 400);
  assert.equal((await ceo.b('DELETE', `/api/admin/roles/${employee.id}`)).status, 400);
  assert.equal((await ceo.b('DELETE', '/api/admin/roles/999999')).status, 404);

  assert.equal((await admin.b('DELETE', `/api/admin/roles/${id}`)).status, 403);
  assert.equal((await ceo.b('DELETE', `/api/admin/roles/${id}`)).status, 204);
  assert.ok((await ceo.b('GET', '/api/roles')).body.roles.every((role) => role.id !== id));
});

test('a role the CEO adds can be given out, and cannot be deleted while someone holds it', async () => {
  const ceo = await app.signInCeo();
  const { body: { role } } = await ceo.b('POST', '/api/admin/roles', { label: 'Contractor', clearance: 1 });
  const { b: casey, user } = await app.signUp('Casey Contractor');

  const assigned = await ceo.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'contractor' });
  assert.equal(assigned.status, 200);
  assert.equal(assigned.body.user.clearance, 1);
  assert.equal((await casey('GET', '/api/me')).body.user.role, 'contractor', 'applies to the open session');
  assert.equal((await casey('GET', '/admin')).location, '/dashboard', 'an added role never opens the console');

  assert.equal((await ceo.b('DELETE', `/api/admin/roles/${role.id}`)).status, 409);
  assert.equal((await ceo.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'employee' })).status, 200);
  assert.equal((await ceo.b('DELETE', `/api/admin/roles/${role.id}`)).status, 204);
});

test('admins give out roles up to their own clearance; only the CEO makes a CEO', async () => {
  const admin = await app.signInAdmin();
  const { user } = await app.signUp('Riley');
  for (const role of ['employee', 'admin', 'intern']) {
    assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/role`, { role })).status, 200, role);
  }
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'ceo' })).status, 403);
  const secondCeo = { name: 'Second CEO', email: app.freshEmail(), password: PASSWORD, role: 'ceo' };
  assert.equal((await admin.b('POST', '/api/admin/users', secondCeo)).status, 403);

  // A clearance-5 role the CEO adds is out of an admin's reach too, and so is everyone in it.
  const ceo = await app.signInCeo();
  const { body: { role: board } } = await ceo.b('POST', '/api/admin/roles', { label: 'Board', clearance: 5 });
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/role`, { role: board.name })).status, 403);
  assert.equal((await ceo.b('PATCH', `/api/admin/users/${user.id}/role`, { role: board.name })).status, 200);
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/password`, { password: 'new-pass-for-riley' })).status, 403);
  assert.equal((await ceo.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'employee' })).status, 200);
});

test("admins can't change the CEO's role, reset their password or delete them", async () => {
  const admin = await app.signInAdmin();
  const ceo = await app.signInCeo();
  const ceoId = ceo.user.id;

  assert.equal((await admin.b('PATCH', `/api/admin/users/${ceoId}/role`, { role: 'employee' })).status, 403);
  assert.equal((await admin.b('PATCH', `/api/admin/users/${ceoId}/password`, { password: 'taken-over-12345' })).status, 403);
  assert.equal((await admin.b('DELETE', `/api/admin/users/${ceoId}`)).status, 403);
  assert.equal((await ceo.b('GET', '/api/me')).status, 200, 'the CEO is still signed in');
  assert.equal((await app.browser()('POST', '/api/login', { email: CEO.email, password: CEO.password, portal: 'admin' })).status, 200);

  // The CEO can manage admins, but not their own role or account.
  assert.equal((await ceo.b('PATCH', `/api/admin/users/${ceoId}/role`, { role: 'admin' })).status, 400);
  assert.equal((await ceo.b('DELETE', `/api/admin/users/${ceoId}`)).status, 400);
});

test('creating, changing and deleting roles is in the activity log', async () => {
  const ceo = await app.signInCeo();
  const { body: { role } } = await ceo.b('POST', '/api/admin/roles', { label: 'Auditors', clearance: 3 });
  await ceo.b('PATCH', `/api/admin/roles/${role.id}`, { clearance: 4 });
  await ceo.b('DELETE', `/api/admin/roles/${role.id}`);

  const { body } = await ceo.b('GET', '/api/admin/audit?limit=50');
  const events = body.events.filter((event) => event.details.role === 'auditors');
  assert.deepEqual(events.map((event) => event.action), ['admin.role_deleted', 'admin.role_updated', 'admin.role_created']);
  assert.deepEqual(events[1].details.from, { label: 'Auditors', clearance: 3 });
  assert.deepEqual(events[1].details.to, { label: 'Auditors', clearance: 4 });
  assert.equal(events[2].actor_email, CEO.email);
});
