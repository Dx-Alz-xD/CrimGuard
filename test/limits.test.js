'use strict';

// Risk limiting: an account whose score crosses a threshold has its clearance cut, so the files
// it can reach shrink. The rule is in src/security/limits.js and applied in the person() CTE in
// db/files.js, so these check both the arithmetic and what it actually does to a file list.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { openDb, createStores } = require('../src/db');
const { capFor, tierFor, TIERS, NO_ACCESS } = require('../src/security/limits');
const { startApp, PASSWORD } = require('./helpers');

const TODAY = new Date().toISOString().slice(0, 10);

// A small world: files at every confidentiality level, all shared with the employee role, so
// clearance is the only thing deciding what is visible.
function world() {
  const db = openDb(':memory:');
  const stores = createStores(db);
  const add = (name, email, role) => stores.users.create({ name, email, role, passwordHash: 'x' });

  const people = {
    employee: add('Emma', 'emma@red.test', 'employee'),
    admin: add('Ada', 'ada@red.test', 'admin'),
    owner: add('Otto', 'otto@red.test', 'employee'),
  };
  const project = stores.projects.create(people.owner.id, { name: 'Shared work', description: '', status: 'active' });
  const employeeRole = stores.roles.byName('employee');

  const files = {};
  for (const level of [1, 2, 3, 4, 5]) {
    const file = stores.files.create(project.id, { name: `level${level}.txt`, type: 'text/plain', content: Buffer.from('x') });
    stores.files.setAccess(file.id, { confidentiality: level, roleIds: [employeeRole.id], userIds: [], grantedBy: people.owner.id });
    files[level] = file;
  }

  const score = (user, value) => stores.risk.setState(user.id, {
    score: value, level: value >= 85 ? 'critical' : value >= 75 ? 'high' : 'low', scoredOn: TODAY,
  });
  // The confidentiality levels a person can reach through a role grant.
  const reach = (user) => stores.files.sharedWith(user.id, user.id).map((file) => file.confidentiality).sort();

  return { db, stores, people, project, files, score, reach };
}

// --- the rule itself ---------------------------------------------------------------------

test('the tiers are ordered so the worse one wins', () => {
  assert.equal(tierFor(95).name, 'tightened');
  assert.equal(tierFor(85).name, 'tightened');
  assert.equal(tierFor(84.9).name, 'reduced');
  assert.equal(tierFor(75).name, 'reduced');
  assert.equal(tierFor(74.9), null);
  assert.equal(tierFor(null), null);
  assert.equal(tierFor(undefined), null);
  // Highest first, or a 90 would match the 75 tier.
  assert.deepEqual(TIERS.map((tier) => tier.minScore), [85, 75]);
});

test('the cap is the average minus the tier drop, and never raises anyone', () => {
  const at = (score, clearance, baseline) => capFor({ score, clearance, baseline });

  // The worked case: an average of 3 holds a limited account to 2, and a worse one to 1.
  assert.equal(at(78, 5, 3).cap, 2);
  assert.equal(at(90, 5, 3).cap, 1);

  // Someone already below the cap keeps what they had: this only ever narrows.
  assert.equal(at(78, 2, 3).cap, 2);
  assert.equal(at(78, 1, 3).cap, 1);
  assert.equal(at(90, 1, 3).limited, false);

  // A low score changes nothing, and neither does an exemption.
  assert.equal(at(50, 4, 3).cap, 4);
  assert.equal(at(50, 4, 3).tier, null);
  assert.equal(capFor({ score: 99, clearance: 4, baseline: 3, exempt: true }).cap, 4);

  // A low average can take the cap below the lowest file level, which means no clearance-based
  // access at all rather than a negative number.
  assert.equal(at(90, 4, 1).cap, NO_ACCESS);
  assert.equal(at(90, 4, 2).cap, NO_ACCESS);

  // With no files there is no average, so there is nothing to measure a cut against.
  assert.equal(at(99, 4, null).cap, 4);
  assert.equal(at(99, 4, null).limited, false);
});

// --- what it does to a file list ------------------------------------------------------------

test('crossing a threshold narrows what an account can actually open', (t) => {
  const { db, stores, people, score, reach } = world();
  t.after(() => db.close());

  assert.equal(stores.risk.baseline(), 3, 'levels 1-5 average to 3');
  assert.deepEqual(reach(people.employee), [1, 2], 'an employee reaches their own clearance of 2');

  score(people.employee, 60);
  assert.deepEqual(reach(people.employee), [1, 2], 'a score below 75 changes nothing');

  score(people.employee, 78);
  assert.equal(stores.risk.limitFor(people.employee.id).tier, 'reduced');

  score(people.employee, 90);
  assert.deepEqual(reach(people.employee), [1], 'at 85 the cap is one below the 75 cap');
  assert.equal(stores.risk.limitFor(people.employee.id).cap, 1);
});

test('an admin is limited the same way, from a higher starting point', (t) => {
  const { db, stores, people, score } = world();
  t.after(() => db.close());

  const levels = () => stores.files.forOwner(people.owner.id, people.admin.id)
    .filter((file) => file.visible).map((file) => file.confidentiality).sort();

  assert.deepEqual(levels(), [1, 2, 3, 4], "an admin's clearance of 4 reaches everything but Secret");
  score(people.admin, 78);
  assert.deepEqual(levels(), [1, 2], 'cut to the 3 average minus one');
  score(people.admin, 88);
  assert.deepEqual(levels(), [1], 'and minus two');
});

test('limiting cuts clearance, not ownership or a grant made by name', (t) => {
  const { db, stores, people, project, score } = world();
  t.after(() => db.close());

  // A Secret file shared with Emma by name, and one Emma owns herself.
  const named = stores.files.create(project.id, { name: 'named-secret', type: 'text/plain', content: Buffer.from('x') });
  stores.files.setAccess(named.id, { confidentiality: 5, roleIds: [], userIds: [people.employee.id], grantedBy: people.owner.id });

  const own = stores.projects.create(people.employee.id, { name: 'Emma own', description: '', status: 'active' });
  const mine = stores.files.create(own.id, { name: 'my-secret', type: 'text/plain', content: Buffer.from('x') });
  stores.files.setAccess(mine.id, { confidentiality: 5, roleIds: [], userIds: [], grantedBy: people.employee.id });

  score(people.employee, 95);

  const shared = stores.files.sharedWith(people.employee.id, people.employee.id).map((file) => file.name).sort();
  assert.deepEqual(shared, ['level1.txt', 'named-secret'],
    'the role grants are cut to level 1, but a file given to her by name is not a clearance decision');
  assert.deepEqual(stores.files.forOwner(people.employee.id, people.employee.id).filter((f) => f.visible).map((f) => f.name),
    ['my-secret'], 'and she keeps her own work');
});

test('an exemption lifts the limit, and removing it puts the limit back', (t) => {
  const { db, stores, people, score, reach } = world();
  t.after(() => db.close());

  score(people.employee, 95);
  assert.deepEqual(reach(people.employee), [1]);

  stores.risk.exempt(people.employee.id, { by: people.admin, reason: 'running the migration' });
  assert.deepEqual(reach(people.employee), [1, 2], 'switched off, she is back to her role clearance');

  const limit = stores.risk.limitFor(people.employee.id);
  assert.equal(limit.limited, false);
  assert.equal(limit.wouldLimit, true, 'the dashboard can still say what is being waived');
  assert.equal(limit.exemption.by, 'Ada');
  assert.equal(limit.exemption.reason, 'running the migration');

  stores.risk.unexempt(people.employee.id);
  assert.deepEqual(reach(people.employee), [1]);
});

test('deleting an account takes its score and exemption with it', (t) => {
  const { db, stores, people, score } = world();
  t.after(() => db.close());

  score(people.employee, 95);
  stores.risk.exempt(people.employee.id, { by: people.admin, reason: '' });
  stores.users.remove(people.employee.id);

  assert.equal(stores.risk.state(people.employee.id), null);
  assert.equal(stores.risk.exemption(people.employee.id), null);
});

// --- who may switch it off --------------------------------------------------------------------

test('an admin cannot waive their own limit, or another admin\'s; the CEO can', async (t) => {
  const app = await startApp();
  t.after(() => app.close());

  const admin = await app.signInAdmin();
  const ceo = await app.signInCeo();
  const { user: worker } = await app.signUp('Wanda');
  const other = await app.signUpAs('admin', 'Other Admin');

  const off = (session, id) => session('PATCH', `/api/crimguard/people/${id}/limit`, { enabled: false, reason: 'testing' });

  // An admin may waive it for someone below them.
  assert.equal((await off(admin.b, worker.id)).status, 200);
  // But not for themselves, and not for another admin.
  assert.equal((await off(admin.b, admin.user.id)).status, 403);
  assert.equal((await off(admin.b, other.user.id)).status, 403);

  // The CEO may do both, including for themselves.
  assert.equal((await off(ceo.b, other.user.id)).status, 200);
  assert.equal((await off(ceo.b, ceo.user.id)).status, 200);

  // And a plain account may not touch it at all.
  const worker2 = await app.signUp('Wes');
  assert.equal((await off(worker2.b, worker.id)).status, 403);
});

test('the record says whether limiting applies and who may change it', async (t) => {
  const app = await startApp();
  t.after(() => app.close());

  const admin = await app.signInAdmin();
  const { user: worker } = await app.signUp('Wanda');

  const record = await admin.b('GET', `/api/crimguard/people/${worker.id}`);
  assert.equal(record.status, 200);
  assert.equal(record.body.limit.limited, false, 'nothing is limited without a score');
  assert.equal(record.body.limit.tier, null);
  assert.equal(record.body.canChangeLimit, true);

  // An admin looking at their own record is told they cannot waive it.
  const own = await admin.b('GET', `/api/crimguard/people/${admin.user.id}`);
  assert.equal(own.body.canChangeLimit, false);

  const toggled = await admin.b('PATCH', `/api/crimguard/people/${worker.id}/limit`, { enabled: false, reason: 'covering for Sam' });
  assert.equal(toggled.status, 200);
  assert.equal(toggled.body.limit.exemption.reason, 'covering for Sam');
  assert.equal(toggled.body.limit.exemption.byRole, 'admin');

  assert.equal((await admin.b('PATCH', `/api/crimguard/people/${worker.id}/limit`, {})).status, 400);
  assert.equal((await admin.b('PATCH', '/api/crimguard/people/999999/limit', { enabled: true })).status, 404);

  const back = await admin.b('PATCH', `/api/crimguard/people/${worker.id}/limit`, { enabled: true });
  assert.equal(back.body.limit.exemption, null);
  void PASSWORD;
});
