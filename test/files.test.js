'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

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

const upload = (b, projectId, name, text, type = 'text/plain') =>
  sendBytes(b, 'POST', `/api/projects/${projectId}/files`, Buffer.from(text), {
    'x-file-name': encodeURIComponent(name),
    'x-file-type': type,
  });

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
