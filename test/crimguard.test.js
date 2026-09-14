'use strict';

// The CrimGuard dashboard: every person and everything Red holds on them, for admins and the CEO.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { connectCrimGuard } = require('../src/db/crimguard');
const { startApp } = require('./helpers');

let app;
before(async () => { app = await startApp(); });
after(() => app.close());

async function uploadFile(b, projectId, name, text, base = app.base) {
  const res = await fetch(`${base}/api/projects/${projectId}/files`, {
    method: 'POST',
    headers: { cookie: b.getCookie(), 'content-type': 'application/octet-stream', 'x-file-name': encodeURIComponent(name) },
    body: Buffer.from(text),
  });
  const body = await res.json();
  assert.equal(res.status, 201, JSON.stringify(body));
  return body.file;
}

const newProject = async (b, name, description = '') => (await b('POST', '/api/projects', { name, description })).body.project;

test('the CrimGuard dashboard is only for admins and the CEO', async () => {
  const anon = app.browser();
  assert.equal((await anon('GET', '/crimguard')).location, '/admin/login');
  assert.equal((await anon('GET', '/api/crimguard/overview')).status, 401);

  const { b: intern } = await app.signUp();
  assert.equal((await intern('GET', '/crimguard')).location, '/dashboard');
  const refused = await intern('GET', '/api/crimguard/overview');
  assert.equal(refused.status, 403);
  assert.equal(refused.body.code, 'not_privileged');
  assert.equal((await intern('GET', '/api/crimguard/people/1')).status, 403);

  for (const signIn of [app.signInAdmin, app.signInCeo]) {
    const { b } = await signIn();
    const page = await b('GET', '/crimguard');
    assert.equal(page.status, 200);
    assert.match(page.body, /CrimGuard/);
    assert.doesNotMatch(page.body, /<title>[^<]*Red/, 'the dashboard carries its own name');
    assert.equal((await b('GET', '/api/crimguard/overview')).status, 200);
  }
});

test('the overview lists everyone with their role, projects, files and whether they are online', async () => {
  const person = await app.signUpAs('employee', 'Otto Overview');
  const project = await newProject(person.b, 'Launch');
  await uploadFile(person.b, project.id, 'a.txt', 'aaaa');
  await uploadFile(person.b, project.id, 'b.txt', 'bb');

  const admin = await app.signInAdmin();
  const { status, body } = await admin.b('GET', '/api/crimguard/overview');
  assert.equal(status, 200);
  assert.equal(body.riskConnected, false);
  assert.equal(body.totals.people, app.db.prepare('SELECT COUNT(*) AS n FROM users').get().n);
  assert.equal(body.people[0].role, 'ceo', 'highest clearance first');

  const row = body.people.find((entry) => entry.id === person.user.id);
  assert.deepEqual(
    [row.role_label, row.clearance, row.project_count, row.file_count, row.file_bytes, row.online, row.risk],
    ['Employee', 2, 1, 2, 6, true, null],
  );
  assert.ok(row.session_count >= 1);
  assert.ok(body.totals.online >= 1);
});

test("a person's record has their profile, projects and files, sessions, shared files and activity", async () => {
  const person = await app.signUpAs('employee', 'Dora Detail');
  const project = await newProject(person.b, 'Research', 'Market sizing');
  await uploadFile(person.b, project.id, 'sizing.csv', 'a,b');
  const giver = await app.signUpAs('employee', 'Gil Giver');
  const handover = await uploadFile(giver.b, (await newProject(giver.b, 'Handover')).id, 'handover.txt', 'notes');

  const admin = await app.signInAdmin();
  await admin.b('PUT', `/api/files/${handover.id}/access`, { confidentiality: 2, people: [person.user.id] });

  const { status, body } = await admin.b('GET', `/api/crimguard/people/${person.user.id}`);
  assert.equal(status, 200);
  assert.equal(body.person.email, person.email);
  assert.equal(body.person.role_label, 'Employee');
  assert.equal(body.person.online, true);
  assert.deepEqual(body.projects.map((p) => [p.name, p.description, p.files.map((f) => f.name), p.hidden_files]), [
    ['Research', 'Market sizing', ['sizing.csv'], 0],
  ]);
  assert.equal(body.totals.files, 1);
  assert.deepEqual(body.shared.map((file) => [file.name, file.owner_name]), [['handover.txt', 'Gil Giver']]);
  assert.ok(body.sessions.length >= 1);
  assert.ok(body.sessions.every((session) => !('token_hash' in session)));
  assert.ok(body.activity.some((event) => event.action === 'account.signup'));
  assert.ok(body.activity.some((event) => event.action === 'crimguard.person_viewed'), 'looking is itself on the record');
  assert.equal(body.risk, null);

  assert.equal((await admin.b('GET', '/api/crimguard/people/999999')).status, 404);
});

test("files above the viewer's clearance are counted but never named", async () => {
  const person = await app.signUpAs('employee', 'Hugo Hidden');
  const project = await newProject(person.b, 'Deals');
  const secret = await uploadFile(person.b, project.id, 'merger-terms.txt', 'secret');
  await uploadFile(person.b, project.id, 'agenda.txt', 'open');
  const ceo = await app.signInCeo();
  assert.equal((await ceo.b('PUT', `/api/files/${secret.id}/access`, { confidentiality: 5 })).status, 200);

  const admin = await app.signInAdmin();
  const seen = await admin.b('GET', `/api/crimguard/people/${person.user.id}`);
  assert.deepEqual(seen.body.projects[0].files.map((file) => file.name), ['agenda.txt']);
  assert.equal(seen.body.projects[0].hidden_files, 1);
  assert.equal(seen.body.totals.hiddenFiles, 1);
  assert.ok(!JSON.stringify(seen.body).includes('merger-terms'));

  const chief = await ceo.b('GET', `/api/crimguard/people/${person.user.id}`);
  assert.deepEqual(chief.body.projects[0].files.map((file) => file.name).sort(), ['agenda.txt', 'merger-terms.txt']);
  assert.equal(chief.body.totals.hiddenFiles, 0);
});

test('opening a record is logged at most once every ten minutes per viewer, however often the page refreshes', async () => {
  let clock = Date.now();
  const timed = await startApp({ now: () => clock });
  try {
    const { user } = await timed.signUp('Wendy Watched');
    const admin = await timed.signInAdmin();
    const views = () => timed.db
      .prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'crimguard.person_viewed' AND target_user_id = ?")
      .get(user.id).n;

    for (let i = 0; i < 5; i += 1) assert.equal((await admin.b('GET', `/api/crimguard/people/${user.id}`)).status, 200);
    assert.equal(views(), 1);

    clock += 11 * 60_000;
    await admin.b('GET', `/api/crimguard/people/${user.id}`);
    assert.equal(views(), 2);

    const ceo = await timed.signInCeo();
    await ceo.b('GET', `/api/crimguard/people/${user.id}`);
    assert.equal(views(), 3, 'each viewer is recorded separately');
  } finally {
    timed.close();
  }
});

test("with the risk database connected, the dashboard adds each person's score", async (t) => {
  const crimguard = await connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });
  const risky = await startApp({ crimguard, riskInterval: 0 });
  const { telemetry } = risky.server;
  t.after(async () => {
    await telemetry.flush();
    risky.close();
    await crimguard.close();
  });

  const person = await risky.signUp('Rhea Risk');
  await newProject(person.b, 'Scored work');
  await telemetry.flush();
  await telemetry.runDay(new Date().toISOString().slice(0, 10));

  const admin = await risky.signInAdmin();
  const overview = await admin.b('GET', '/api/crimguard/overview');
  assert.equal(overview.status, 200);
  assert.equal(overview.body.riskConnected, true);
  const row = overview.body.people.find((entry) => entry.id === person.user.id);
  assert.ok(row.risk, 'the scored person carries a risk entry');
  assert.equal(typeof row.risk.score, 'number');

  const detail = await admin.b('GET', `/api/crimguard/people/${person.user.id}`);
  assert.equal(detail.status, 200);
  assert.ok(detail.body.risk.history.length >= 1);
});
