'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { connectCrimGuard } = require('../src/db/crimguard');
const { isDecoyId, DECOY_ID_BASE } = require('../src/telemetry/honeytokens');
const { startApp, PASSWORD } = require('./helpers');

let app;
before(async () => { app = await startApp(); });
after(() => app.close());

// Sends raw bytes with a simulated browser's cookie, the way the upload UI does.
async function sendBytes(b, method, url, bytes, headers = {}, base = app.base) {
  const res = await fetch(base + url, {
    method,
    headers: { cookie: b.getCookie(), 'content-type': 'application/octet-stream', ...headers },
    body: bytes,
  });
  const isJson = (res.headers.get('content-type') || '').includes('application/json');
  return { status: res.status, headers: res.headers, body: isJson ? await res.json() : Buffer.from(await res.arrayBuffer()) };
}

const upload = (b, projectId, name, text, type = 'text/plain', base = app.base) =>
  sendBytes(b, 'POST', `/api/projects/${projectId}/files`, Buffer.from(text), {
    'x-file-name': encodeURIComponent(name),
    'x-file-type': type,
  }, base);

async function newProject(b, name = 'Files project') {
  const res = await b('POST', '/api/projects', { name });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return res.body.project;
}

test('files upload to your own project, list without their contents, and download unchanged', async () => {
  const { b } = await app.signUp('Filer');
  const project = await newProject(b);

  const created = await upload(b, project.id, 'Kickoff notés.txt', 'hello files');
  assert.equal(created.status, 201, JSON.stringify(created.body));
  assert.equal(created.body.file.name, 'Kickoff notés.txt');
  assert.equal(created.body.file.size, 11);
  assert.equal(created.body.file.type, 'text/plain');

  const list = await b('GET', `/api/projects/${project.id}/files`);
  assert.equal(list.status, 200);
  assert.deepEqual(list.body.files.map((f) => f.name), ['Kickoff notés.txt']);
  assert.ok(list.body.maxFileBytes > 0);
  assert.ok(list.body.files.every((f) => !('content' in f)));

  const download = await sendBytes(b, 'GET', `/api/projects/${project.id}/files/${created.body.file.id}/download`);
  assert.equal(download.status, 200);
  assert.equal(download.body.toString(), 'hello files');
  assert.equal(download.headers.get('content-type'), 'application/octet-stream');
  assert.equal(download.headers.get('x-content-type-options'), 'nosniff');
  assert.match(download.headers.get('content-security-policy'), /sandbox/);
  assert.equal(download.headers.get('content-disposition'), `attachment; filename="Kickoff not_s.txt"; filename*=UTF-8''Kickoff%20not%C3%A9s.txt`);

  const projects = (await b('GET', '/api/projects')).body.projects;
  assert.equal(projects.find((p) => p.id === project.id).file_count, 1);
});

test('uploads must be raw bytes from this site, and every other write must still be JSON', async () => {
  const { b } = await app.signUp();
  const project = await newProject(b);
  const url = `/api/projects/${project.id}/files`;

  assert.equal((await b('POST', url, { name: 'x.txt' }, { 'x-file-name': 'x.txt' })).status, 415);
  assert.equal((await sendBytes(b, 'POST', url, Buffer.from('x'), { 'content-type': 'text/plain', 'x-file-name': 'x.txt' })).status, 415);
  assert.equal((await sendBytes(b, 'POST', '/api/projects', Buffer.from('{}'))).status, 415);
  assert.equal((await sendBytes(b, 'POST', url, Buffer.from('x'), { 'x-file-name': 'x.txt', 'sec-fetch-site': 'cross-site' })).status, 403);

  assert.equal((await upload(b, project.id, '', 'no name')).status, 400);
  assert.equal((await sendBytes(b, 'POST', url, Buffer.from('x'), { 'x-file-name': '%E0%A4%A' })).status, 400);
});

test('file names are cleaned, unique per project ignoring case, and renamed safely', async () => {
  const { b } = await app.signUp();
  const project = await newProject(b);

  const report = await upload(b, project.id, '../../etc/Report.PDF', 'v1', 'application/pdf');
  assert.equal(report.status, 201, JSON.stringify(report.body));
  assert.equal(report.body.file.name, 'Report.PDF');
  assert.equal((await upload(b, project.id, 'report.pdf', 'other')).status, 409);

  const notes = (await upload(b, project.id, 'notes.txt', 'n')).body.file;
  assert.equal((await b('PATCH', `/api/projects/${project.id}/files/${notes.id}`, { name: 'REPORT.pdf' })).status, 409);
  assert.equal((await b('PATCH', `/api/projects/${project.id}/files/${notes.id}`, { name: '   ' })).status, 400);

  const renamed = await b('PATCH', `/api/projects/${project.id}/files/${report.body.file.id}`, { name: 'report-final.pdf' });
  assert.equal(renamed.status, 200);
  assert.equal(renamed.body.file.name, 'report-final.pdf');
  // Changing only the case of a file's own name is not a clash.
  assert.equal((await b('PATCH', `/api/projects/${project.id}/files/${report.body.file.id}`, { name: 'Report-Final.pdf' })).status, 200);
});

test('replacing a file keeps its name and swaps in the new contents', async () => {
  const { b } = await app.signUp();
  const project = await newProject(b);
  const { file } = (await upload(b, project.id, 'budget.csv', 'a,b\n1,2', 'text/csv')).body;

  const replaced = await sendBytes(b, 'PUT', `/api/projects/${project.id}/files/${file.id}/content`, Buffer.from('a,b\n1,2\n3,4'), { 'x-file-type': 'text/csv' });
  assert.equal(replaced.status, 200, JSON.stringify(replaced.body));
  assert.equal(replaced.body.file.name, 'budget.csv');
  assert.equal(replaced.body.file.size, 11);

  const download = await sendBytes(b, 'GET', `/api/projects/${project.id}/files/${file.id}/download`);
  assert.equal(download.body.toString(), 'a,b\n1,2\n3,4');
});

test("files are private: nobody else can reach a project's files, admins included", async () => {
  const owner = await app.signUp('Owner');
  const other = await app.signUp('Other');
  const admin = await app.signInAdmin();
  const project = await newProject(owner.b);
  const { file } = (await upload(owner.b, project.id, 'secret.txt', 'top secret')).body;

  for (const intruder of [other.b, admin.b]) {
    assert.equal((await intruder('GET', `/api/projects/${project.id}/files`)).status, 404);
    assert.equal((await upload(intruder, project.id, 'sneaky.txt', 'x')).status, 404);
    assert.equal((await sendBytes(intruder, 'GET', `/api/projects/${project.id}/files/${file.id}/download`)).status, 404);
    assert.equal((await intruder('PATCH', `/api/projects/${project.id}/files/${file.id}`, { name: 'mine.txt' })).status, 404);
    assert.equal((await sendBytes(intruder, 'PUT', `/api/projects/${project.id}/files/${file.id}/content`, Buffer.from('x'))).status, 404);
    assert.equal((await intruder('DELETE', `/api/projects/${project.id}/files/${file.id}`)).status, 404);
  }

  // A file id can't be reached through a different project, even one the requester owns.
  const theirs = await newProject(other.b);
  assert.equal((await sendBytes(other.b, 'GET', `/api/projects/${theirs.id}/files/${file.id}/download`)).status, 404);
  assert.equal((await upload(app.browser(), project.id, 'anon.txt', 'x')).status, 401);
  assert.equal((await sendBytes(owner.b, 'GET', `/api/projects/${project.id}/files/${file.id}/download`)).body.toString(), 'top secret');
});

test('uploads over the size limit are refused', async () => {
  const small = await startApp({ maxFileBytes: 16 });
  try {
    const { b } = await small.signUp();
    const project = (await b('POST', '/api/projects', { name: 'Small' })).body.project;
    const send = (name, size) =>
      sendBytes(b, 'POST', `/api/projects/${project.id}/files`, Buffer.alloc(size), { 'x-file-name': name }, small.base);
    assert.equal((await send('fits.bin', 16)).status, 201);
    const tooBig = await send('too-big.bin', 17);
    assert.equal(tooBig.status, 413);
    assert.match(tooBig.body.error, /up to 16 bytes/);
  } finally {
    small.close();
    small.db.close();
  }
});

test('deleting a file, a project or an account removes the stored contents', async () => {
  const { b, user } = await app.signUp('Cascade');
  const keep = await newProject(b, 'Keep');
  const drop = await newProject(b, 'Drop');
  const one = (await upload(b, keep.id, 'one.txt', '1')).body.file;
  await upload(b, keep.id, 'two.txt', '2');
  await upload(b, drop.id, 'three.txt', '3');
  const filesIn = (...ids) =>
    app.db.prepare(`SELECT COUNT(*) AS n FROM project_files WHERE project_id IN (${ids.map(() => '?').join(', ')})`).get(...ids).n;

  assert.equal((await b('DELETE', `/api/projects/${keep.id}/files/${one.id}`)).status, 204);
  assert.equal((await b('DELETE', `/api/projects/${keep.id}/files/${one.id}`)).status, 404);
  assert.equal(filesIn(keep.id), 1);

  assert.equal((await b('DELETE', `/api/projects/${drop.id}`)).status, 204);
  assert.equal(filesIn(drop.id), 0);

  const admin = await app.signInAdmin();
  assert.equal((await admin.b('DELETE', `/api/admin/users/${user.id}`)).status, 204);
  assert.equal(filesIn(keep.id, drop.id), 0);
});

// --- decoy projects and the CrimGuard risk database ---------------------------------------

// An app with the risk database attached, set up the same way as in telemetry.test.js.
async function startWithRisk() {
  const crimguard = await connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });
  const risky = await startApp({ crimguard, riskInterval: 0 });
  const telemetry = risky.server.telemetry;
  return {
    ...risky,
    crimguard,
    telemetry,
    async close() {
      await telemetry.flush();
      risky.close();
      await crimguard.close();
    },
  };
}

// Signs someone up and plants a decoy in their project list; returns the decoy as their list shows it.
async function signUpWithDecoy(risky, name) {
  const person = await risky.signUp(name);
  await person.b('GET', '/api/projects');
  await risky.telemetry.flush();
  await risky.telemetry.honeytokens.plantIfNeeded(person.user.id, 95);
  const decoy = (await person.b('GET', '/api/projects')).body.projects.find((project) => isDecoyId(project.id));
  assert.ok(decoy, 'a decoy was planted');
  return { ...person, decoy };
}

test('without a planted decoy, an id in the decoy range is just a project that does not exist', async () => {
  const { b } = await app.signUp();
  const id = DECOY_ID_BASE + 1;
  assert.equal((await b('GET', `/api/projects/${id}/files`)).status, 404);
  assert.equal((await upload(b, id, 'x.txt', 'x')).status, 404);
  assert.equal((await b('GET', '/api/me')).status, 200, 'nothing was tripped');
});

test('opening a decoy shows an empty project, and downloading from it finds nothing', async (t) => {
  const risky = await startWithRisk();
  t.after(() => risky.close());
  const { b, decoy } = await signUpWithDecoy(risky, 'Curious');

  const opened = await b('GET', `/api/projects/${decoy.id}/files`);
  assert.equal(opened.status, 200);
  assert.deepEqual(opened.body.files, []);
  assert.equal((await sendBytes(b, 'GET', `/api/projects/${decoy.id}/files/1/download`, undefined, {}, risky.base)).status, 404);

  assert.equal((await b('GET', '/api/me')).status, 200, 'looking is not a trip');
  const { rows } = await risky.crimguard.query('SELECT COUNT(*) AS n FROM honeytoken_triggers');
  assert.equal(Number(rows[0].n), 0);
});

test('uploading to a decoy trips it: every session is revoked and the trip is recorded', async (t) => {
  const risky = await startWithRisk();
  t.after(() => risky.close());
  const { b, email, decoy } = await signUpWithDecoy(risky, 'Took The Bait');

  // Signed in on a second device, to check the revocation reaches everywhere.
  const phone = risky.browser();
  assert.equal((await phone('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200);

  const attempt = await upload(b, decoy.id, 'loot.txt', 'mine now', 'text/plain', risky.base);
  assert.equal(attempt.status, 401, 'refused as signed-out, which sends the browser to the login page');
  assert.equal((await b('GET', '/api/me')).status, 401, 'this session is gone');
  assert.equal((await phone('GET', '/api/me')).status, 401, 'and so is every other one');

  const { rows } = await risky.crimguard.query('SELECT interaction FROM honeytoken_triggers');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].interaction, 'modified');
});

test('file actions reach the risk database as accesses to their project', async (t) => {
  const risky = await startWithRisk();
  t.after(() => risky.close());
  const { b } = await risky.signUp('Recorded');
  const project = (await b('POST', '/api/projects', { name: 'Tracked' })).body.project;

  const { file } = (await upload(b, project.id, 'report.txt', 'report body', 'text/plain', risky.base)).body;
  assert.equal((await sendBytes(b, 'GET', `/api/projects/${project.id}/files/${file.id}/download`, undefined, {}, risky.base)).status, 200);
  assert.equal((await b('PATCH', `/api/projects/${project.id}/files/${file.id}`, { name: 'report-final.txt' })).status, 200);
  assert.equal((await b('DELETE', `/api/projects/${project.id}/files/${file.id}`)).status, 204);
  await risky.telemetry.flush();

  const { rows } = await risky.crimguard.query('SELECT action FROM file_access_events');
  const actions = rows.map((row) => row.action);
  for (const action of ['write', 'download', 'rename', 'delete']) {
    assert.ok(actions.includes(action), `a ${action} was recorded (saw: ${actions.join(', ')})`);
  }
});
