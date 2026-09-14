'use strict';

// Who can see a file: confidentiality 1-5, role clearance, and sharing with roles or people.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

let app;
before(async () => { app = await startApp(); });
after(() => app.close());

// A new project holding one uploaded file.
async function uploadFile(b, name, text = 'contents') {
  const project = (await b('POST', '/api/projects', { name: `Project for ${name}` })).body.project;
  const res = await fetch(`${app.base}/api/projects/${project.id}/files`, {
    method: 'POST',
    headers: { cookie: b.getCookie(), 'content-type': 'application/octet-stream', 'x-file-name': encodeURIComponent(name), 'x-file-type': 'text/plain' },
    body: Buffer.from(text),
  });
  const body = await res.json();
  assert.equal(res.status, 201, JSON.stringify(body));
  return { project, file: body.file };
}

const openStatus = async (b, file) => (await b('GET', `/api/files/${file.id}/download`)).status;
// A file above the opener's clearance asks for a code first (test/above-clearance-download.test.js).
async function openStatusWithCode(b, file) {
  const held = await b('GET', `/api/files/${file.id}/download`);
  if (held.body?.code !== 'download_mfa_required') return held.status;
  assert.equal((await b('POST', `/api/files/${file.id}/download/verify`, { code: '123456' })).status, 200);
  return openStatus(b, file);
}
const setAccess = (b, file, body) => b('PUT', `/api/files/${file.id}/access`, body);
const roleId = async (b, name) => (await b('GET', '/api/roles')).body.roles.find((role) => role.name === name).id;
const sharedWith = async (b) => (await b('GET', '/api/files/shared')).body.files;

test('a new file is Internal and unshared: its owner, admins and the CEO can open it, nobody else', async () => {
  const owner = await app.signUpAs('employee', 'Olive Owner');
  const other = await app.signUpAs('employee', 'Eddie Employee');
  const { file } = await uploadFile(owner.b, 'plan.txt', 'the plan');
  assert.equal(file.confidentiality, 2);
  assert.equal(file.shared_roles, 0);
  assert.equal(file.shared_people, 0);

  const admin = await app.signInAdmin();
  const ceo = await app.signInCeo();
  const download = await owner.b('GET', `/api/files/${file.id}/download`);
  assert.equal(download.status, 200);
  assert.equal(download.body, 'the plan');
  assert.equal(download.headers.get('content-type'), 'application/octet-stream');
  assert.equal(await openStatus(admin.b, file), 200);
  assert.equal(await openStatus(ceo.b, file), 200);
  assert.equal(await openStatus(other.b, file), 404, 'not even told the file exists');
  assert.ok((await sharedWith(other.b)).every((entry) => entry.id !== file.id));
});

test("sharing with a role reaches its members while the role's clearance covers the file", async () => {
  const owner = await app.signUpAs('employee', 'Rita Roles');
  const colleague = await app.signUpAs('employee', 'Cole League');
  const intern = await app.signUp('Ian Intern');
  const admin = await app.signInAdmin();
  const { project, file } = await uploadFile(owner.b, 'roadmap.txt');
  const employees = await roleId(admin.b, 'employee');

  const shared = await setAccess(admin.b, file, { confidentiality: 2, roles: [employees] });
  assert.equal(shared.status, 200, JSON.stringify(shared.body));
  assert.deepEqual(shared.body.roles.map((role) => role.name), ['employee']);
  assert.equal(shared.body.canManage, true);

  assert.equal(await openStatus(colleague.b, file), 200);
  const entry = (await sharedWith(colleague.b)).find((item) => item.id === file.id);
  assert.equal(entry.by_name, false);
  assert.equal(entry.owner_name, 'Rita Roles');
  assert.equal(entry.project_name, project.name);
  assert.equal(await openStatus(intern.b, file), 404, 'interns are not in the role');
  assert.ok((await sharedWith(owner.b)).every((item) => item.id !== file.id), 'your own files are not shared with you');

  // Confidential (3) is above an employee's clearance (2), so the same grant stops working.
  assert.equal((await setAccess(admin.b, file, { confidentiality: 3, roles: [employees] })).status, 200);
  assert.equal(await openStatus(colleague.b, file), 404);
  assert.ok((await sharedWith(colleague.b)).every((item) => item.id !== file.id));

  const listed = (await owner.b('GET', `/api/projects/${project.id}/files`)).body.files[0];
  assert.deepEqual([listed.confidentiality, listed.shared_roles, listed.shared_people], [3, 1, 0]);
});

test('a role the CEO adds with more clearance can be given more confidential files', async () => {
  const ceo = await app.signInCeo();
  const { body: { role: analysts } } = await ceo.b('POST', '/api/admin/roles', { label: 'Analysts', clearance: 3 });
  const owner = await app.signUpAs('employee', 'Owen');
  const analyst = await app.signUpAs('analysts', 'Ana Lyst');
  const { file } = await uploadFile(owner.b, 'forecast.txt');

  await setAccess(ceo.b, file, { confidentiality: 3, roles: [analysts.id] });
  assert.equal(await openStatus(analyst.b, file), 200);
  await setAccess(ceo.b, file, { confidentiality: 4, roles: [analysts.id] });
  assert.equal(await openStatus(analyst.b, file), 404);
});

test('sharing with a person works at any confidentiality, and removing them takes effect at once', async () => {
  const owner = await app.signUpAs('employee', 'Paula');
  const intern = await app.signUp('Nia');
  const admin = await app.signInAdmin();
  const { file } = await uploadFile(owner.b, 'salaries.txt');

  const granted = await setAccess(admin.b, file, { confidentiality: 4, people: [intern.user.id, owner.user.id, intern.user.id] });
  assert.equal(granted.status, 200, JSON.stringify(granted.body));
  assert.deepEqual(granted.body.people.map((person) => person.id), [intern.user.id], 'the owner is never on the list, and nobody is on it twice');
  assert.equal(await openStatusWithCode(intern.b, file), 200);
  assert.equal((await sharedWith(intern.b)).find((item) => item.id === file.id).by_name, true);

  await setAccess(admin.b, file, { confidentiality: 4, people: [] });
  assert.equal(await openStatus(intern.b, file), 404);
});

test("Secret files are the CEO's: admins can't open, mark or unlock them", async () => {
  const owner = await app.signUpAs('employee', 'Sam Secret');
  const admin = await app.signInAdmin();
  const ceo = await app.signInCeo();
  const { file } = await uploadFile(owner.b, 'acquisition.txt');

  assert.equal((await setAccess(admin.b, file, { confidentiality: 5 })).status, 403);
  assert.equal((await setAccess(ceo.b, file, { confidentiality: 5 })).status, 200);

  assert.equal(await openStatus(admin.b, file), 404);
  assert.equal((await admin.b('GET', `/api/files/${file.id}/access`)).status, 404);
  assert.equal((await setAccess(admin.b, file, { confidentiality: 4 })).status, 404);
  assert.equal(await openStatus(owner.b, file), 200, 'the owner always can');
  assert.equal(await openStatus(ceo.b, file), 200);

  // The CEO can let one admin in by name. That admin can open it, but still can't change it.
  await setAccess(ceo.b, file, { confidentiality: 5, people: [admin.user.id] });
  assert.equal(await openStatusWithCode(admin.b, file), 200);
  assert.equal((await admin.b('GET', `/api/files/${file.id}/access`)).body.canManage, false);
  assert.equal((await setAccess(admin.b, file, { confidentiality: 4, people: [] })).status, 403);
});

test('only admins and the CEO change access; owners can see who has it; input is checked', async () => {
  const owner = await app.signUpAs('employee', 'Vera');
  const friend = await app.signUp('Finn');
  const admin = await app.signInAdmin();
  const { file } = await uploadFile(owner.b, 'brief.txt');

  const refused = await setAccess(owner.b, file, { confidentiality: 1, people: [friend.user.id] });
  assert.equal(refused.status, 403);
  assert.equal((await setAccess(friend.b, file, { confidentiality: 1 })).status, 403);

  assert.equal((await setAccess(admin.b, file, { confidentiality: 2, people: [friend.user.id] })).status, 200);
  const ownerView = await owner.b('GET', `/api/files/${file.id}/access`);
  assert.equal(ownerView.status, 200);
  assert.equal(ownerView.body.canManage, false);
  assert.deepEqual(ownerView.body.people.map((person) => person.name), ['Finn']);
  assert.equal((await friend.b('GET', `/api/files/${file.id}/access`)).status, 403, 'being given a file is not being told who else has it');

  const invalid = [
    {}, { confidentiality: 0 }, { confidentiality: 6 }, { confidentiality: 2.5 },
    { confidentiality: 2, roles: 'employee' }, { confidentiality: 2, roles: [999999] },
    { confidentiality: 2, people: [999999] }, { confidentiality: 2, people: [-1] },
  ];
  for (const body of invalid) assert.equal((await setAccess(admin.b, file, body)).status, 400, JSON.stringify(body));
  assert.equal((await setAccess(admin.b, { id: 999999 }, { confidentiality: 2 })).status, 404);
});

test('grants go with the role, the person or the file they were for', async () => {
  const ceo = await app.signInCeo();
  const owner = await app.signUpAs('employee', 'Gina');
  const guest = await app.signUp('Gus');
  const { body: { role: temps } } = await ceo.b('POST', '/api/admin/roles', { label: 'Temps', clearance: 2 });
  const { project, file } = await uploadFile(owner.b, 'rota.txt');
  const grants = (table) => app.db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE file_id = ?`).get(file.id).n;

  await setAccess(ceo.b, file, { confidentiality: 2, roles: [temps.id], people: [guest.user.id] });
  assert.deepEqual([grants('file_role_grants'), grants('file_user_grants')], [1, 1]);

  assert.equal((await ceo.b('DELETE', `/api/admin/roles/${temps.id}`)).status, 204);
  assert.equal(grants('file_role_grants'), 0);
  assert.equal((await ceo.b('DELETE', `/api/admin/users/${guest.user.id}`)).status, 204);
  assert.equal(grants('file_user_grants'), 0);

  const another = await app.signUp('Hal');
  await setAccess(ceo.b, file, { confidentiality: 2, people: [another.user.id] });
  assert.equal((await owner.b('DELETE', `/api/projects/${project.id}/files/${file.id}`)).status, 204);
  assert.equal(grants('file_user_grants'), 0);
  assert.equal(await openStatus(another.b, file), 404);
});

test("opening someone else's file and changing access are both in the activity log", async () => {
  const owner = await app.signUpAs('employee', 'Lou Logged');
  const reader = await app.signUp('Rae Reader');
  const admin = await app.signInAdmin();
  const { file } = await uploadFile(owner.b, 'minutes.txt');

  await setAccess(admin.b, file, { confidentiality: 3, people: [reader.user.id] });
  // Given a minute ago, so this is an ordinary download rather than a grab (which is logged too).
  app.db.prepare("UPDATE file_user_grants SET granted_at = datetime('now', '-60 seconds') WHERE file_id = ?").run(file.id);
  assert.equal(await openStatusWithCode(reader.b, file), 200);
  assert.equal(await openStatus(owner.b, file), 200);

  // Matched on the owner as well as the id: SQLite can reuse the id of a file deleted by an earlier test.
  const { body } = await admin.b('GET', '/api/admin/audit?limit=50');
  const events = body.events.filter((event) => event.details.file === file.id && event.target_email === owner.email);
  assert.deepEqual(events.map((event) => event.action), ['file.downloaded', 'file.access_changed'], 'an owner opening their own file is not logged');
  assert.equal(events[0].actor_email, reader.email);
  assert.equal(events[0].target_email, owner.email);
  assert.deepEqual(events[1].details.confidentiality, { from: 2, to: 3 });
  assert.ok(!JSON.stringify(events).includes('minutes.txt'), 'file names stay out of the log');
});
