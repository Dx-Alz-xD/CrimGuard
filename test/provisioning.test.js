'use strict';

// Two ways access arrives without anyone granting it file by file:
//   - a project shared with a role, which covers its files including later ones
//   - a new account provisioned from the people who already hold its role

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { openDb, createStores } = require('../src/db');
const { planFor, peerAverage } = require('../src/security/provisioning');
const { startApp, PASSWORD } = require('./helpers');

// Raw bytes, the way the upload UI sends them.
async function upload(app, b, projectId, name, text = 'x') {
  const res = await fetch(`${app.base}/api/projects/${projectId}/files`, {
    method: 'POST',
    headers: { cookie: b.getCookie(), 'content-type': 'application/octet-stream', 'x-file-name': encodeURIComponent(name) },
    body: Buffer.from(text),
  });
  return (await res.json()).file;
}

function world() {
  const db = openDb(':memory:');
  const stores = createStores(db);
  const add = (name, email, role) => stores.users.create({ name, email, role, passwordHash: 'x' });
  const owner = add('Otto', 'otto@red.test', 'employee');
  const project = stores.projects.create(owner.id, { name: 'Onboarding', description: '', status: 'active' });

  const file = (name, confidentiality) => {
    const created = stores.files.create(project.id, { name, type: 'text/plain', content: Buffer.from('x') });
    stores.files.setAccess(created.id, { confidentiality, roleIds: [], userIds: [], grantedBy: owner.id });
    return created;
  };
  const reach = (user) => stores.files.sharedWith(user.id, user.id).map((f) => f.name).sort();
  return { db, stores, add, owner, project, file, reach };
}

// --- a project shared with a role ---------------------------------------------------------

test('sharing a project with a role covers its files, including ones added later', (t) => {
  const { db, stores, add, owner, project, file, reach } = world();
  t.after(() => db.close());

  file('handbook.txt', 1);
  file('plan.txt', 2);
  file('board-pack.txt', 4);

  const intern = add('Ivy', 'ivy@red.test', 'intern');
  const employee = add('Emma', 'emma@red.test', 'employee');
  assert.deepEqual(reach(intern), [], 'nothing is shared to begin with');

  stores.files.setProjectRoles(project.id, {
    roleIds: [stores.roles.byName('intern').id, stores.roles.byName('employee').id],
    grantedBy: owner.id,
  });

  // Clearance still decides: sharing a project does not hand out what the role can't hold.
  assert.deepEqual(reach(intern), ['handbook.txt'], 'an intern has clearance 1');
  assert.deepEqual(reach(employee), ['handbook.txt', 'plan.txt'], 'an employee has clearance 2');

  // A file added afterwards is covered, which is the reason to share a project rather than files.
  file('added-later.txt', 1);
  assert.deepEqual(reach(intern), ['added-later.txt', 'handbook.txt']);

  // Taking the role off the list takes the access with it.
  stores.files.setProjectRoles(project.id, { roleIds: [stores.roles.byName('employee').id], grantedBy: owner.id });
  assert.deepEqual(reach(intern), []);
  assert.equal(stores.files.projectRoles(project.id).map((role) => role.name).join(), 'employee');
});

test('a project can only be shared by its owner, and only with roles that exist', async (t) => {
  const app = await startApp();
  t.after(() => app.close());

  const alice = await app.signUp('Alice');
  const bob = await app.signUp('Bob');
  const project = (await alice.b('POST', '/api/projects', { name: 'Mine' })).body.project;
  const roles = (await alice.b('GET', '/api/roles')).body.roles;
  const internRole = roles.find((role) => role.name === 'intern');

  // Someone else's project is indistinguishable from one that doesn't exist.
  assert.equal((await bob.b('GET', `/api/projects/${project.id}/access`)).status, 404);
  assert.equal((await bob.b('PUT', `/api/projects/${project.id}/access`, { roles: [internRole.id] })).status, 404);

  const shared = await alice.b('PUT', `/api/projects/${project.id}/access`, { roles: [internRole.id] });
  assert.equal(shared.status, 200, JSON.stringify(shared.body));
  assert.deepEqual(shared.body.roles.map((role) => role.name), ['intern']);

  assert.equal((await alice.b('PUT', `/api/projects/${project.id}/access`, { roles: [999999] })).status, 400);
  assert.equal((await alice.b('PUT', `/api/projects/${project.id}/access`, { roles: 'all of them' })).status, 400);
  assert.equal((await alice.b('PUT', `/api/projects/${project.id}/access`, { roles: [-1] })).status, 400);

  // Clearing the list is how sharing is undone.
  assert.deepEqual((await alice.b('PUT', `/api/projects/${project.id}/access`, { roles: [] })).body.roles, []);
  void PASSWORD;
});

// --- provisioning a new account from its peers ----------------------------------------------

test('the target is the peer average, rounded, and capped', () => {
  assert.equal(peerAverage([]), 0);
  assert.equal(peerAverage([2, 2, 2]), 2);
  assert.equal(peerAverage([1, 2]), 2, 'rounded up, so a role where most have one still gives one');
  assert.equal(peerAverage([1, 1, 2]), 1);
  assert.equal(peerAverage([0, 0, 0]), 0);

  const peers = [{ fileIds: [1, 2, 3, 4] }, { fileIds: [1, 2, 3, 4] }];
  const candidates = [1, 2, 3, 4].map((id) => ({ id, confidentiality: 1 }));
  assert.equal(planFor({ peers, candidates, clearance: 5, max: 2 }).granted.length, 2, 'the ceiling holds');
});

test('a newcomer gets the files their role-mates most commonly have, within clearance', () => {
  // Three interns: all three hold the handbook, two hold the guide, one holds a level-4 file.
  const peers = [
    { fileIds: [1, 2] },
    { fileIds: [1, 2] },
    { fileIds: [1, 9] },
  ];
  const candidates = [
    { id: 1, confidentiality: 1 },
    { id: 2, confidentiality: 1 },
    { id: 9, confidentiality: 4 },
  ];

  const plan = planFor({ peers, candidates, clearance: 1 });
  assert.equal(plan.peers, 3);
  assert.equal(plan.target, 2, 'two files each, on average');
  assert.deepEqual(plan.granted, [1, 2], 'the two most widely held, most-shared first');
  assert.ok(!plan.granted.includes(9), 'the level-4 file is above an intern and is never offered');

  // Nobody to copy means no precedent, so nothing is granted.
  assert.deepEqual(planFor({ peers: [], candidates, clearance: 5 }).granted, []);
  // Peers who hold nothing set a target of nothing.
  assert.deepEqual(planFor({ peers: [{ fileIds: [] }, { fileIds: [] }], candidates, clearance: 5 }).granted, []);
});

test('a tie is settled towards the less confidential file', () => {
  const peers = [{ fileIds: [7, 8] }];
  const candidates = [{ id: 7, confidentiality: 3 }, { id: 8, confidentiality: 1 }];
  // One peer with two files: the target is 2, so ask for one to see which is preferred.
  const plan = planFor({ peers, candidates, clearance: 5, max: 1 });
  assert.deepEqual(plan.granted, [8]);
});

test('signing up inherits what the other interns already have', async (t) => {
  const app = await startApp();
  t.after(() => app.close());

  const admin = await app.signInAdmin();
  // The owner is an employee, so the intern peer group is only the interns. An owner needs no
  // grants of their own, and counting them as an intern holding nothing would drag the average
  // down - which is exactly what the last assertion in this test checks.
  const owner = await app.signUpAs('employee', 'Otto');
  const project = (await owner.b('POST', '/api/projects', { name: 'Onboarding' })).body.project;

  const handbook = await upload(app, owner.b, project.id, 'handbook.txt');
  const guide = await upload(app, owner.b, project.id, 'guide.txt');

  // Two interns already hold both files.
  const first = await app.signUp('Ivy');
  const second = await app.signUp('Ian');
  for (const file of [handbook, guide]) {
    const res = await admin.b('PUT', `/api/files/${file.id}/access`, {
      confidentiality: 1, roles: [], people: [first.user.id, second.user.id],
    });
    assert.equal(res.status, 200, JSON.stringify(res.body));
  }

  // A third signs up and should start where they did.
  const newcomer = await app.signUp('Nina');
  const shared = (await newcomer.b('GET', '/api/files/shared')).body.files.map((file) => file.name).sort();
  assert.deepEqual(shared, ['guide.txt', 'handbook.txt'], 'provisioned from the interns already here');

  // Every holder of the role counts, including ones with nothing: the newcomer above now holds
  // two files, so a fourth intern is averaged over 2, 2 and 2 and still gets two. Had someone
  // in the role held nothing, the average - and the grant - would be smaller.
  const fourth = await app.signUp('Ford');
  assert.equal((await fourth.b('GET', '/api/files/shared')).body.files.length, 2);
});

test('the first account of a role has no precedent and starts with nothing', async (t) => {
  const app = await startApp();
  t.after(() => app.close());

  const lonely = await app.signUpAs('employee', 'Lonely');
  assert.deepEqual((await lonely.b('GET', '/api/files/shared')).body.files, []);
});

test('provisioning never hands out more than the role may hold', async (t) => {
  const app = await startApp();
  t.after(() => app.close());

  const admin = await app.signInAdmin();
  const owner = await app.signUp('Otto');
  const project = (await owner.b('POST', '/api/projects', { name: 'Sensitive' })).body.project;
  const file = await upload(app, owner.b, project.id, 'board-pack.txt');

  // One intern was given a Restricted file by name, which is allowed: a named grant ignores
  // clearance. Provisioning must not repeat it, because that is a clearance decision.
  const holder = await app.signUp('Ivy');
  assert.equal((await admin.b('PUT', `/api/files/${file.id}/access`, {
    confidentiality: 4, roles: [], people: [holder.user.id],
  })).status, 200);

  const newcomer = await app.signUp('Nina');
  assert.deepEqual((await newcomer.b('GET', '/api/files/shared')).body.files, [],
    'an intern does not inherit a Restricted file just because another intern was handed one');
});
