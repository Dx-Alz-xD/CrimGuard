'use strict';

// Departure gating: while someone is working their notice, a file shared with them by name that
// sits above their clearance needs an admin to release it.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createStores } = require('../src/db');
const { connectCrimGuard } = require('../src/db/crimguard');
const { gateFor, daysUntil, isDeparting, NOTICE_WINDOW_DAYS, APPROVAL_DAYS } = require('../src/security/departure');
const { startApp, PASSWORD, ADMIN } = require('./helpers');

const DAY = 86400000;
const NOW = Date.parse('2026-09-14T12:00:00Z');
const inDays = (n, from = NOW) => new Date(from + n * DAY).toISOString().slice(0, 10);

// --- the rule, on its own ----------------------------------------------------------------------

test('days until a date, and what counts as leaving', () => {
  assert.equal(daysUntil(inDays(10), NOW), 10);
  assert.equal(daysUntil(inDays(0), NOW), 0);
  assert.equal(daysUntil(inDays(-3), NOW), -3, 'a date that has passed is negative');
  assert.equal(daysUntil(null, NOW), null, 'almost every account has no date at all');
  assert.equal(daysUntil('not-a-date', NOW), null);

  assert.equal(isDeparting(inDays(NOTICE_WINDOW_DAYS, NOW), NOW), true, 'the far edge of the window is inside it');
  assert.equal(isDeparting(inDays(NOTICE_WINDOW_DAYS + 1, NOW), NOW), false, 'a day beyond it is not');
  assert.equal(isDeparting(inDays(-1, NOW), NOW), true, 'a leaving date that has passed on an open account still counts');
  assert.equal(isDeparting(null, NOW), false);
});

test('the gate holds exactly one case: by name, above clearance, on the way out', () => {
  const base = { terminationDate: inDays(5), confidentiality: 4, clearance: 2, byName: true, now: NOW };
  assert.equal(gateFor(base).gated, true);
  assert.equal(gateFor(base).reason, 'needs_approval');

  assert.equal(gateFor({ ...base, terminationDate: null }).gated, false, 'nobody is leaving');
  assert.equal(gateFor({ ...base, terminationDate: inDays(60) }).gated, false, 'not yet in the window');
  assert.equal(gateFor({ ...base, confidentiality: 2 }).gated, false, 'their clearance already covers it');
  assert.equal(gateFor({ ...base, byName: false }).gated, false, 'reached through a role, which clearance already judges');
  assert.equal(gateFor({ ...base, isOwner: true }).gated, false, 'their own file, on their way out or not');

  const live = new Date(NOW + 2 * DAY).toISOString();
  const stale = new Date(NOW - 2 * DAY).toISOString();
  assert.equal(gateFor({ ...base, approvedUntil: live }).gated, false, 'an admin released it');
  assert.equal(gateFor({ ...base, approvedUntil: stale }).gated, true, 'and the release ran out');
  assert.equal(gateFor({ ...base, approvedUntil: stale }).reason, 'approval_expired');
});

// --- end to end --------------------------------------------------------------------------------

let app;
let stores;
before(async () => {
  app = await startApp();
  stores = createStores(app.db);
});
after(() => app.close());

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

// An employee (clearance 2) holding a Restricted file (4) shared with them by name — the one
// combination risk limiting deliberately leaves open.
async function restrictedShare(name, { confidentiality = 4, sharer = null } = {}) {
  const owner = await app.signUpAs('employee', `${name} Owner`);
  const person = await app.signUpAs('employee', name);
  const by = sharer || (await app.signInAdmin());
  const { file } = await uploadFile(owner.b, `${name.toLowerCase().replace(/\W+/g, '-')}.txt`, 'the crown jewels');
  const shared = await by.b('PUT', `/api/files/${file.id}/access`, { confidentiality, roles: [], people: [person.user.id] });
  assert.equal(shared.status, 200, JSON.stringify(shared.body));
  return { owner, person, file, admin: by };
}

const leaves = (userId, days) => stores.departures.setState(userId, { terminationDate: inDays(days, Date.now()) });

test('with nobody leaving, a by-name share above clearance opens exactly as it did before', async () => {
  const { person, file } = await restrictedShare('Stacy Staying');
  const res = await person.b('GET', `/api/files/${file.id}/download`);
  assert.equal(res.status, 200);
  assert.equal(res.body, 'the crown jewels');
});

test('inside the notice window the same download is refused, and the file is still listed', async () => {
  const { person, file } = await restrictedShare('Lee Leaving');
  leaves(person.user.id, 5);

  const res = await person.b('GET', `/api/files/${file.id}/download`);
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'access_request_required');
  assert.match(res.body.error, /above their clearance of 2/);
  assert.equal(res.body.details.file.id, file.id);
  assert.equal(res.body.details.daysLeft, 5);
  assert.equal(res.body.details.request, null, 'nothing asked for yet');

  // Refusing is not hiding: they have to be able to see it to ask for it.
  const listed = (await person.b('GET', '/api/files/shared')).body.files;
  assert.ok(listed.some((entry) => entry.id === file.id), 'the file is still in Shared with me');
});

test('a file their clearance already covers, and their own files, are never gated', async () => {
  const { person, file } = await restrictedShare('Ivy Internal', { confidentiality: 2 });
  leaves(person.user.id, 3);
  assert.equal((await person.b('GET', `/api/files/${file.id}/download`)).status, 200, 'level 2 is within an employee clearance');

  const own = await uploadFile(person.b, 'my-own-work.txt', 'mine');
  assert.equal((await person.b('GET', `/api/files/${own.file.id}/download`)).status, 200, 'their own work stays theirs');
});

test('asking, approving, and then the file opens', async () => {
  const { person, file, admin } = await restrictedShare('Rex Requesting');
  leaves(person.user.id, 7);

  const asked = await person.b('POST', `/api/files/${file.id}/access-request`, { reason: 'Finishing the migration doc' });
  assert.equal(asked.status, 201, JSON.stringify(asked.body));
  assert.equal(asked.body.request.status, 'pending');
  assert.equal(asked.body.request.reason, 'Finishing the migration doc');

  // Asking twice is the same ask.
  const again = await person.b('POST', `/api/files/${file.id}/access-request`, { reason: 'again' });
  assert.equal(again.status, 200);
  assert.equal(again.body.request.id, asked.body.request.id, 'the queue does not fill up with duplicates');

  // It reaches the admin console with everything needed to judge it.
  const queue = await admin.b('GET', '/api/admin/access-requests?status=pending');
  assert.equal(queue.status, 200);
  const entry = queue.body.requests.find((r) => r.id === asked.body.request.id);
  assert.ok(entry, 'the request is in the queue');
  assert.equal(entry.file.name, 'rex-requesting.txt');
  assert.equal(entry.file.confidentiality, 4);
  assert.equal(entry.person.id, person.user.id);
  assert.equal(entry.person.daysLeft, 7);
  assert.match(entry.explanation, /leaving in 7 days/);
  assert.ok(queue.body.leaving.some((p) => p.id === person.user.id), 'and so does who is leaving');

  // Still refused until somebody decides.
  assert.equal((await person.b('GET', `/api/files/${file.id}/download`)).status, 403);

  const decided = await admin.b('POST', `/api/admin/access-requests/${asked.body.request.id}/decision`, { decision: 'approve', note: 'ok until Friday' });
  assert.equal(decided.status, 200, JSON.stringify(decided.body));
  assert.equal(decided.body.request.status, 'approved');
  assert.ok(decided.body.request.expiresAt, 'an approval is a key with a life on it');

  const opened = await person.b('GET', `/api/files/${file.id}/download`);
  assert.equal(opened.status, 200);
  assert.equal(opened.body, 'the crown jewels');

  // And the person can see what came back.
  const mine = await person.b('GET', '/api/me/access-requests');
  assert.equal(mine.body.requests[0].status, 'approved');
  assert.equal(mine.body.requests[0].decidedBy, ADMIN.name);
});

test('a denial leaves the file shut, and a decided request cannot be decided twice', async () => {
  const { person, file, admin } = await restrictedShare('Deb Denied');
  leaves(person.user.id, 2);
  const asked = await person.b('POST', `/api/files/${file.id}/access-request`, { reason: 'please' });
  const id = asked.body.request.id;

  const denied = await admin.b('POST', `/api/admin/access-requests/${id}/decision`, { decision: 'deny', note: 'no' });
  assert.equal(denied.status, 200);
  assert.equal(denied.body.request.status, 'denied');
  assert.equal((await person.b('GET', `/api/files/${file.id}/download`)).status, 403, 'still shut');

  const twice = await admin.b('POST', `/api/admin/access-requests/${id}/decision`, { decision: 'approve' });
  assert.equal(twice.status, 409, 'somebody already decided it');
});

test('an approval expires on its own', () => {
  const person = stores.users.create({ name: 'Ex Pired', email: `expired-${Math.random().toString(36).slice(2)}@red.test`, role: 'employee', passwordHash: 'x' });
  const owner = stores.users.create({ name: 'Own Er', email: `owner-${Math.random().toString(36).slice(2)}@red.test`, role: 'employee', passwordHash: 'x' });
  const project = stores.projects.create(owner.id, { name: 'P', description: '', status: 'active' });
  const file = stores.files.create(project.id, { name: 'f.txt', type: 'text/plain', content: Buffer.from('abc') });
  stores.files.setAccess(file.id, { confidentiality: 4, roleIds: [], userIds: [person.id], grantedBy: owner.id });
  stores.departures.setState(person.id, { terminationDate: inDays(3, Date.now()) });

  const ask = { userId: person.id, fileId: file.id, confidentiality: 4, clearance: 2 };
  const { request } = stores.departures.request({ ...ask, reason: 'work' });
  // Approved a fortnight ago, so its life has run out.
  const longAgo = Date.now() - (APPROVAL_DAYS + 7) * DAY;
  stores.departures.decide(request.id, { approve: true, by: { id: owner.id, name: 'Own Er' }, now: longAgo });

  const gate = stores.departures.gate({ ...ask, ownerId: owner.id });
  assert.equal(gate.gated, true);
  assert.equal(gate.reason, 'approval_expired');
});

test('releasing a file takes the clearance the file itself needs', async () => {
  const ceo = await app.signInCeo();
  const { person, file } = await restrictedShare('Sam Secret', { confidentiality: 5, sharer: ceo });
  const admin = await app.signInAdmin();
  leaves(person.user.id, 4);
  const asked = await person.b('POST', `/api/files/${file.id}/access-request`, { reason: 'need it' });
  const id = asked.body.request.id;

  const byAdmin = await admin.b('POST', `/api/admin/access-requests/${id}/decision`, { decision: 'approve' });
  assert.equal(byAdmin.status, 403, 'an admin cannot approve their way into a Secret file');

  const byCeo = await ceo.b('POST', `/api/admin/access-requests/${id}/decision`, { decision: 'approve' });
  assert.equal(byCeo.status, 200, JSON.stringify(byCeo.body));
  assert.equal((await person.b('GET', `/api/files/${file.id}/download`)).status, 200);
});

test('the queue is admins only, and asking is refused for a file that is not gated', async () => {
  const { person, file } = await restrictedShare('Nora Normal');
  assert.equal((await person.b('GET', '/api/admin/access-requests')).status, 403);
  assert.equal((await person.b('POST', `/api/files/${file.id}/access-request`, {})).status, 400, 'nothing to ask for');
  assert.equal((await person.b('POST', '/api/files/999999/access-request', {})).status, 404);
});

// --- the leaving date arrives from HR ----------------------------------------------------------

test('a leaving date recorded in the risk console reaches the gate', async (t) => {
  const crimguard = await connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });
  const hrApp = await startApp({ crimguard, riskInterval: 0 });
  t.after(async () => { hrApp.close(); await crimguard.close(); });
  const hrStores = createStores(hrApp.db);

  const person = await hrApp.signUpAs('employee', 'Hank Aitch-Arr');
  const admin = await hrApp.signInAdmin();
  // Signing up already created the CrimGuard person; HR context hangs off that row.
  await hrApp.server.telemetry.flush();
  const { rows } = await crimguard.query('SELECT id FROM users WHERE okta_user_id = ?', [`red:${person.user.id}`]);
  assert.equal(rows.length, 1, 'the sign-up created the CrimGuard person');
  const crimId = rows[0].id;

  assert.equal(hrStores.departures.terminationDate(person.user.id), null, 'nothing on file to begin with');

  const leaving = inDays(9, Date.now());
  const patched = await admin.b('PATCH', `/api/admin/risk/people/${crimId}`, { terminationDate: leaving });
  assert.equal(patched.status, 200, JSON.stringify(patched.body));
  assert.equal(hrStores.departures.terminationDate(person.user.id), leaving, 'and now the gate can see it');

  // Clearing it puts everything back.
  const cleared = await admin.b('PATCH', `/api/admin/risk/people/${crimId}`, { terminationDate: null });
  assert.equal(cleared.status, 200, JSON.stringify(cleared.body));
  assert.equal(hrStores.departures.terminationDate(person.user.id), null);

  // A resignation notice is a departure too, and the amplifier already treats it as one.
  const notice = await admin.b('POST', `/api/admin/risk/people/${crimId}/hr-events`, {
    type: 'resignation_notice', effectiveDate: inDays(11, Date.now()),
  });
  assert.equal(notice.status, 201, JSON.stringify(notice.body));
  assert.equal(hrStores.departures.terminationDate(person.user.id), inDays(11, Date.now()));
});
