'use strict';

// Downloading a file above your clearance: a code before every download, and a grab within
// seconds of being given the file raises the score.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createStores } = require('../src/db');
const { RAPID_DOWNLOAD, DOWNLOAD_MFA, aboveClearance, secondsSince, rapidDownload } = require('../src/security/above-clearance');
const { startApp, PASSWORD } = require('./helpers');

const CODE = '123456';

// --- the rules, on their own -------------------------------------------------------------------

test('above clearance means someone else\'s file, marked higher than the clearance they have', () => {
  assert.equal(aboveClearance({ confidentiality: 4, clearance: 2 }), true);
  assert.equal(aboveClearance({ confidentiality: 2, clearance: 2 }), false, 'at their clearance is within it');
  assert.equal(aboveClearance({ confidentiality: 1, clearance: 2 }), false);
  assert.equal(aboveClearance({ confidentiality: 5, clearance: 2, isOwner: true }), false, 'their own file never is');
});

test('a grab is a download within five whole seconds of being given the file', () => {
  const given = '2026-09-15 10:00:00'; // how SQLite's datetime('now') stores it, in UTC
  const at = (seconds) => Date.parse('2026-09-15T10:00:00Z') + seconds * 1000;

  assert.equal(secondsSince(given, at(3.4)), 3);
  assert.equal(secondsSince('2026-09-15T10:00:00.000Z', at(2)), 2, 'ISO text reads the same');
  assert.equal(secondsSince(null, at(1)), null);

  assert.equal(rapidDownload({ accessSince: given, now: at(0) }).rapid, true, 'the same second');
  assert.equal(rapidDownload({ accessSince: given, now: at(RAPID_DOWNLOAD.windowSeconds + 0.9) }).rapid, true, 'still within the fifth second');
  assert.equal(rapidDownload({ accessSince: given, now: at(RAPID_DOWNLOAD.windowSeconds + 1) }).rapid, false, 'six seconds is not');
  assert.equal(rapidDownload({ accessSince: null, now: at(1) }).rapid, false, 'never given it by name or by approval');
  assert.equal(rapidDownload({ accessSince: given, now: at(-3) }).rapid, false, 'a clock that runs backwards proves nothing');
});

// --- end to end --------------------------------------------------------------------------------

let app;
let stores;
before(async () => {
  app = await startApp();
  stores = createStores(app.db);
});
after(() => app.close());

async function uploadFile(b, name, text) {
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

// An employee (clearance 2) given a file by name at `confidentiality`.
async function share(name, { confidentiality = 4 } = {}) {
  const owner = await app.signUpAs('employee', `${name} Owner`);
  const person = await app.signUpAs('employee', name);
  const admin = await app.signInAdmin();
  const { file } = await uploadFile(owner.b, `${name.toLowerCase().replace(/\W+/g, '-')}.txt`, 'the crown jewels');
  const shared = await admin.b('PUT', `/api/files/${file.id}/access`, { confidentiality, roles: [], people: [person.user.id] });
  assert.equal(shared.status, 200, JSON.stringify(shared.body));
  return { owner, person, file, admin };
}

// Moves the grant into the past, so the download that follows is not a grab.
const givenSecondsAgo = (fileId, userId, seconds) =>
  app.db.prepare("UPDATE file_user_grants SET granted_at = datetime('now', ?) WHERE file_id = ? AND user_id = ?")
    .run(`-${seconds} seconds`, fileId, userId);

const grabs = (userId) => stores.signals.adjustments(userId).filter((a) => a.kind === RAPID_DOWNLOAD.kind);
const download = (b, fileId) => b('GET', `/api/files/${fileId}/download`);
const verify = (b, fileId, code) => b('POST', `/api/files/${fileId}/download/verify`, { code });

test('a download straight after the share is held for a code, and raises the score', async () => {
  const { person, file } = await share('Gary Grabber');
  stores.risk.setState(person.user.id, { score: 30, level: 'low', scoredOn: '2026-09-15' });

  const held = await download(person.b, file.id);
  assert.equal(held.status, 403);
  assert.equal(held.body.code, 'download_mfa_required');
  assert.match(held.body.error, /above your clearance of 2/);
  assert.equal(held.body.details.file.id, file.id);
  assert.equal(held.body.details.remaining, DOWNLOAD_MFA.maxAttempts);

  const [grab] = grabs(person.user.id);
  assert.ok(grab, 'the grab is recorded before the code is even asked for');
  assert.equal(grab.delta, RAPID_DOWNLOAD.delta);
  assert.equal(grab.detail.file, file.id);
  assert.ok(grab.detail.seconds <= RAPID_DOWNLOAD.windowSeconds);
  assert.ok(Date.parse(grab.expiresAt) > Date.now(), 'and it expires on its own');
  assert.equal(stores.signals.effective(person.user.id, 30), 30 + RAPID_DOWNLOAD.delta, 'the score limiting acts on goes up');
  assert.ok(stores.audit.list().some((row) => row.action === 'risk.rapid_download' && row.actor_id === person.user.id));

  const wrong = await verify(person.b, file.id, '000000');
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.code, 'download_mfa_failed');
  assert.equal(wrong.body.details.remaining, DOWNLOAD_MFA.maxAttempts - 1);
  assert.equal((await download(person.b, file.id)).status, 403, 'a wrong code opens nothing');

  const right = await verify(person.b, file.id, CODE);
  assert.equal(right.status, 200, JSON.stringify(right.body));
  const opened = await download(person.b, file.id);
  assert.equal(opened.status, 200);
  assert.equal(opened.body, 'the crown jewels');

  assert.equal(grabs(person.user.id).length, 1, 'retrying after the code is the same grab, not a second one');
  assert.equal(stores.signals.effective(person.user.id, 30), 30 + RAPID_DOWNLOAD.delta, 'and it does not stack');
});

test('one code is one download', async () => {
  const { person, file } = await share('Una Once');
  givenSecondsAgo(file.id, person.user.id, 60);

  assert.equal((await verify(person.b, file.id, CODE)).status, 200);
  assert.equal((await download(person.b, file.id)).status, 200);
  const again = await download(person.b, file.id);
  assert.equal(again.status, 403, 'the code was spent');
  assert.equal(again.body.code, 'download_mfa_required');
});

test('taking a while to open a shared file still asks for the code, but is not a grab', async () => {
  const { person, file } = await share('Pat Patient');
  givenSecondsAgo(file.id, person.user.id, 60);

  const held = await download(person.b, file.id);
  assert.equal(held.status, 403);
  assert.equal(held.body.code, 'download_mfa_required');
  assert.deepEqual(grabs(person.user.id), [], 'a minute later is just opening it');
});

test('files within clearance, and your own files, download without a code', async () => {
  const { person, file } = await share('Ivy Inside', { confidentiality: 2 });
  assert.equal((await download(person.b, file.id)).status, 200, 'level 2 is within an employee clearance');
  assert.equal((await verify(person.b, file.id, CODE)).status, 400, 'and there is no code to give for it');

  const own = await uploadFile(person.b, 'mine.txt', 'mine');
  assert.equal((await download(person.b, own.file.id)).status, 200);
  assert.deepEqual(grabs(person.user.id), []);
});

test('a code is for this session only', async () => {
  const { person, file } = await share('Sid Sessions');
  givenSecondsAgo(file.id, person.user.id, 60);
  assert.equal((await verify(person.b, file.id, CODE)).status, 200);

  const elsewhere = app.browser();
  const signedIn = await elsewhere('POST', '/api/login', { email: person.email, password: PASSWORD, portal: 'user' });
  assert.equal(signedIn.status, 200, JSON.stringify(signedIn.body));
  assert.equal((await download(elsewhere, file.id)).status, 403, 'another device has to enter its own');
  assert.equal((await download(person.b, file.id)).status, 200, 'and the session that entered it can still use it');
});

test('a code left unused runs out', async () => {
  const { person, file } = await share('Walt Waited');
  givenSecondsAgo(file.id, person.user.id, 600);
  assert.equal((await verify(person.b, file.id, CODE)).status, 200);
  app.db.prepare('UPDATE download_verifications SET verified_at = ? WHERE file_id = ?')
    .run(new Date(Date.now() - DOWNLOAD_MFA.validForMs - 1000).toISOString(), file.id);
  assert.equal((await download(person.b, file.id)).status, 403);
});

test('too many wrong codes shut the file on that session', async () => {
  const { person, file } = await share('Lou Locked');
  for (let i = 1; i < DOWNLOAD_MFA.maxAttempts; i += 1) {
    assert.equal((await verify(person.b, file.id, '999999')).status, 400);
  }
  const last = await verify(person.b, file.id, '999999');
  assert.equal(last.status, 403);
  assert.equal(last.body.code, 'download_mfa_locked');

  assert.equal((await verify(person.b, file.id, CODE)).body.code, 'download_mfa_locked', 'the right code is too late');
  const shut = await download(person.b, file.id);
  assert.equal(shut.status, 403);
  assert.equal(shut.body.code, 'download_mfa_locked');
  assert.ok(stores.audit.list().some((row) => row.action === 'security.download_mfa_locked' && row.actor_id === person.user.id));
});

test('an admin releasing a file to someone leaving counts as giving it to them', async () => {
  const { person, file, admin } = await share('Rhea Released');
  givenSecondsAgo(file.id, person.user.id, 3600);
  stores.departures.setState(person.user.id, { terminationDate: new Date(Date.now() + 5 * 86400000).toISOString().slice(0, 10) });

  const asked = await person.b('POST', `/api/files/${file.id}/access-request`, { reason: 'handover' });
  assert.equal(asked.status, 201, JSON.stringify(asked.body));
  const decided = await admin.b('POST', `/api/admin/access-requests/${asked.body.request.id}/decision`, { decision: 'approve' });
  assert.equal(decided.status, 200, JSON.stringify(decided.body));

  assert.equal((await download(person.b, file.id)).body.code, 'download_mfa_required');
  assert.equal(grabs(person.user.id).length, 1, 'downloading the moment it was released is a grab');
});
