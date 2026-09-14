'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { DEFAULT_POLICIES, policyFor, biometricAction, standing } = require('../src/identity/policy');
const { createIdentity } = require('../src/identity/identity');
const { connectCrimGuard } = require('../src/db/crimguard');
const { createTelemetry } = require('../src/telemetry');
const { createSubjects } = require('../src/telemetry/subjects');
const { startApp, PASSWORD, ADMIN } = require('./helpers');

const quiet = () => {};
const today = () => new Date().toISOString().slice(0, 10);
const enabled = DEFAULT_POLICIES.map((p, i) => ({ ...p, id: i + 1, isEnabled: true, requiresApproval: false }));

// --- the rules ---------------------------------------------------------------------------------------

test('the strongest matching policy wins, and a scenario policy needs its scenario', () => {
  assert.equal(policyFor({ score: 50 }, enabled), null);
  assert.equal(policyFor({ score: 72 }, enabled).action, 'step_up_mfa');
  assert.equal(policyFor({ score: 93 }, enabled).action, 'session_freeze', 'a freeze outranks a step-up');
  assert.equal(policyFor({ score: 100, scenario: 'honeytoken_trip' }, enabled).name, 'Freeze on a honeytoken trip');
  assert.equal(policyFor({ score: 55, scenario: 'credential_compromise' }, enabled).action, 'step_up_mfa');
  assert.equal(policyFor({ score: 93 }, enabled.map((p) => ({ ...p, isEnabled: p.action !== 'session_freeze' }))).action, 'step_up_mfa', 'disabled policies are skipped');
});

test('biometrics are judged together with the score', () => {
  assert.equal(biometricAction({ decision: 'ok' }, { score: 95 }), null);
  assert.equal(biometricAction({ decision: 'watch' }, { score: 20 }), null, 'drift alone is only watched');
  assert.equal(biometricAction({ decision: 'watch' }, { score: 45 }).reason, 'biometric_drift_with_risk_anomaly');
  assert.equal(biometricAction({ decision: 'challenge' }, null).action, 'step_up_mfa');
  assert.equal(biometricAction({ decision: 'challenge', suddenChange: true }, { score: 10 }).reason, 'biometric_change_mid_session');
  assert.equal(biometricAction({ decision: 'challenge' }, { score: 61 }).action, 'session_freeze');
});

test('standing: a restore clears what came before it, and a session step-up belongs to its session', () => {
  const actions = [
    { id: 1, action: 'session_freeze', status: 'completed', payload: {} },
    { id: 2, action: 'restore_access', status: 'completed', payload: {} },
    { id: 3, action: 'step_up_mfa', status: 'sent', payload: { sessionRef: 'abc' } },
    { id: 4, action: 'session_freeze', status: 'pending', payload: {} },
  ];
  const mine = standing(actions, 'abc');
  assert.deepEqual([mine.frozen, mine.stepUp, mine.pending.length], [false, true, 1]);
  assert.equal(standing(actions, 'other-session').stepUp, false);
  assert.equal(standing([...actions, { id: 5, action: 'session_freeze', status: 'completed', payload: {} }]).frozen, true);
});

// --- in the app ----------------------------------------------------------------------------------------

async function withIdentity(t) {
  const crimguard = await connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });
  const app = await startApp({ crimguard, riskInterval: 0, protectionOptions: { log: quiet, honeytrapInterval: 0, honeytrapOptions: { log: quiet } } });
  t.after(async () => {
    await app.server.telemetry.flush();
    app.close();
    await crimguard.close();
  });
  const subjects = createSubjects(crimguard);
  const { identity } = app.server.protection;
  let version = 0;

  async function score(user, finalScore, scenario = null) {
    const crimId = await subjects.forUser(user);
    const { rows: existing } = await crimguard.query('SELECT id FROM risk_feature_snapshot WHERE user_id = ? AND snapshot_date = ?', [crimId, today()]);
    const snapshot = existing[0]?.id ?? (await crimguard.query(
      'INSERT INTO risk_feature_snapshot (user_id, snapshot_date, period_start, period_end) VALUES (?, ?, ?, ?) RETURNING id',
      [crimId, today(), `${today()}T00:00:00.000Z`, `${today()}T23:59:59.000Z`],
    )).rows[0].id;
    version += 1;
    const level = finalScore >= 80 ? 'critical' : finalScore >= 60 ? 'high' : finalScore >= 40 ? 'medium' : 'low';
    await crimguard.query('INSERT INTO risk_scores (snapshot_id, user_id, model_version, final_score, risk_level, scenario, scored_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [snapshot, crimId, `v${version}`, finalScore, level, scenario, new Date(Date.now() + version).toISOString()]);
    await app.server.protection.onScored({ crimUserId: crimId });
    return crimId;
  }

  const actionsOf = async (crimId) => (await crimguard.query('SELECT action, status, policy_id, request_payload FROM identity_actions WHERE user_id = ? ORDER BY id', [crimId])).rows;
  const login = (email, password = PASSWORD, portal = 'user') => app.browser()('POST', '/api/login', { email, password, portal });
  return { app, crimguard, identity, score, actionsOf, login };
}

test('a score over the step-up policy holds every session of the account until the password is confirmed', async (t) => {
  const { app, score, actionsOf, login } = await withIdentity(t);
  const { b, email, user } = await app.signUp('Stella Stepup');
  const laptop = app.browser();
  assert.equal((await laptop('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200);
  const crimId = await score(user, 74);

  for (const browser of [b, laptop]) {
    const res = await browser('GET', '/api/projects');
    assert.deepEqual([res.status, res.body.code], [403, 'step_up_required'], 'a score policy applies to every session');
  }
  assert.equal((await b('GET', '/api/me')).status, 200, 'who am I, sign-out and the step-up itself stay open');
  assert.deepEqual((await b('GET', '/api/identity/status')).body, { frozen: false, stepUp: true });
  assert.equal((await login(email)).status, 200, 'a step-up is not a lock: signing in still works');

  const [action] = await actionsOf(crimId);
  assert.deepEqual([action.action, action.status, action.request_payload.source], ['step_up_mfa', 'sent', 'risk_policy']);
  assert.match(action.request_payload.reasons[0], /Step-up at risk score 70: score 74\.0 \(high\)/);

  assert.equal((await b('POST', '/api/identity/step-up', { password: 'nope-nope-nope' })).status, 400);
  assert.equal((await b('POST', '/api/identity/step-up', { password: PASSWORD })).body.status, 'verified');
  assert.equal((await b('GET', '/api/projects')).status, 200);
  assert.equal((await laptop('GET', '/api/projects')).status, 200);

  await score(user, 76);
  assert.equal((await actionsOf(crimId)).length, 1, 'the same policy does not fire again the same day');
  assert.equal((await b('GET', '/api/projects')).status, 200);
});

test('a score too high freezes the account, and an admin restores it', async (t) => {
  const { app, score, actionsOf, login } = await withIdentity(t);
  const { b, email, user } = await app.signUp('Frieda Frozen');
  const crimId = await score(user, 74);
  await score(user, 93); // escalates past the open step-up the same day

  assert.equal((await b('GET', '/api/me')).status, 401, 'every session has ended');
  const refused = await login(email);
  assert.deepEqual([refused.status, refused.body.code], [403, 'account_frozen']);
  assert.deepEqual((await actionsOf(crimId)).map((a) => `${a.action}:${a.status}`), ['step_up_mfa:sent', 'session_freeze:completed']);

  const admin = await app.signInAdmin();
  const overview = await admin.b('GET', '/api/admin/identity');
  const person = overview.body.people.find((p) => p.crimUserId === crimId);
  assert.deepEqual([person.frozen, person.email], [true, email]);
  assert.equal(overview.body.policies.length, DEFAULT_POLICIES.length);

  assert.equal((await b('POST', `/api/admin/identity/people/${crimId}/restore`, {})).status, 401, 'not by the person themself');
  const restored = await admin.b('POST', `/api/admin/identity/people/${crimId}/restore`, { note: 'Spoke to Frieda; migration work.' });
  assert.deepEqual([restored.status, restored.body.wasFrozen, restored.body.cancelled], [200, true, 1]);
  assert.equal((await login(email)).status, 200);
  const back = await actionsOf(crimId);
  assert.deepEqual(back.map((a) => `${a.action}:${a.status}`), ['step_up_mfa:cancelled', 'session_freeze:completed', 'restore_access:completed']);
  assert.equal(back[2].request_payload.note, 'Spoke to Frieda; migration work.');
  assert.ok(app.stores ? true : true);
});

test('a policy that needs approval waits for an analyst, who can approve or decline it', async (t) => {
  const { app, score, actionsOf } = await withIdentity(t);
  const admin = await app.signInAdmin();
  const { policies } = (await admin.b('GET', '/api/admin/identity')).body;
  const freeze = policies.find((p) => p.name === 'Freeze at risk score 90');
  const stepUp = policies.find((p) => p.name === 'Step-up at risk score 70');
  assert.equal((await admin.b('PATCH', `/api/admin/identity/policies/${freeze.id}`, { requiresApproval: true })).body.policy.requiresApproval, true);
  assert.equal((await admin.b('PATCH', `/api/admin/identity/policies/${stepUp.id}`, { requiresApproval: true, minFinalScore: 65 })).body.policy.minFinalScore, 65);
  assert.equal((await admin.b('PATCH', `/api/admin/identity/policies/${stepUp.id}`, { minFinalScore: 140 })).status, 400);
  assert.equal((await admin.b('PATCH', `/api/admin/identity/policies/${stepUp.id}`, { minFinalScore: null })).status, 400, 'a policy with no scenario needs a threshold');

  const one = await app.signUp('Pending Pat');
  const crimOne = await score(one.user, 95);
  assert.equal((await one.b('GET', '/api/projects')).status, 200, 'nothing happens before approval');
  const [pending] = (await admin.b('GET', '/api/admin/identity')).body.people.find((p) => p.crimUserId === crimOne).actions;
  assert.equal(pending.status, 'pending');
  assert.equal((await one.b('POST', `/api/admin/identity/actions/${pending.id}/approve`)).status, 403);
  assert.equal((await admin.b('POST', `/api/admin/identity/actions/${pending.id}/approve`)).status, 200);
  assert.equal((await one.b('GET', '/api/projects')).status, 401, 'approved: frozen');
  assert.equal((await admin.b('POST', `/api/admin/identity/actions/${pending.id}/approve`)).status, 404, 'only once');

  const two = await app.signUp('Declined Dee');
  const crimTwo = await score(two.user, 67);
  const [waiting] = (await actionsOf(crimTwo));
  assert.equal(waiting.status, 'pending');
  const [row] = (await admin.b('GET', '/api/admin/identity')).body.people.find((p) => p.crimUserId === crimTwo).actions;
  assert.equal((await admin.b('POST', `/api/admin/identity/actions/${row.id}/decline`)).status, 200);
  assert.equal((await two.b('GET', '/api/projects')).status, 200);
  assert.equal((await actionsOf(crimTwo))[0].status, 'cancelled');
  assert.ok(app.stores ? true : true);
});

test('three wrong passwords at a step-up freeze the account', async (t) => {
  const { app, score, actionsOf, login } = await withIdentity(t);
  const { b, email, user } = await app.signUp('Guessing Gus');
  const crimId = await score(user, 71);
  assert.equal((await b('POST', '/api/identity/step-up', { password: 'guess-one-1' })).status, 400);
  assert.equal((await b('POST', '/api/identity/step-up', { password: 'guess-two-2' })).status, 400);
  assert.equal((await b('POST', '/api/identity/step-up', { password: 'guess-three-3' })).status, 401);
  assert.equal((await login(email)).body.code, 'account_frozen');
  const actions = await actionsOf(crimId);
  assert.deepEqual(actions.map((a) => `${a.action}:${a.status}`), ['step_up_mfa:failed', 'session_freeze:completed']);
  assert.equal(actions[1].request_payload.source, 'step_up_failed');
});

test('the last admin is never locked out: a freeze becomes a step-up until another admin can restore', async (t) => {
  const { app, crimguard, score, actionsOf, login } = await withIdentity(t);
  const admin = await app.signInAdmin();
  const adminUser = (await admin.b('GET', '/api/me')).body.user;
  const crimAdmin = await score(adminUser, 97);
  const [action] = await actionsOf(crimAdmin);
  assert.deepEqual([action.action, action.request_payload.downgradedFrom], ['step_up_mfa', 'session_freeze']);
  assert.equal((await login(ADMIN.email, ADMIN.password, 'admin')).status, 200);
  assert.equal((await admin.b('GET', '/api/admin/users')).body.code, 'step_up_required');
  assert.equal((await admin.b('POST', '/api/identity/step-up', { password: ADMIN.password })).status, 200);

  // With a second admin, the same thing is a real freeze.
  const second = await app.signUp('Second Admin');
  assert.equal((await admin.b('PATCH', `/api/admin/users/${second.user.id}/role`, { role: 'admin' })).status, 200);
  await crimguard.query('DELETE FROM identity_actions WHERE user_id = ?', [crimAdmin]);
  await crimguard.query('DELETE FROM risk_scores WHERE user_id = ?', [crimAdmin]);
  await score(adminUser, 98);
  assert.equal((await actionsOf(crimAdmin)).at(-1).action, 'session_freeze');
  assert.equal((await login(ADMIN.email, ADMIN.password, 'admin')).body.code, 'account_frozen');
});

test('scoring calls the throttle for the day it scored, so a policy acts as soon as the score exists', async () => {
  const crimguard = await connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });
  try {
    const calls = [];
    const telemetry = createTelemetry(crimguard, { onScored: (event) => calls.push(event) });
    const user = { id: 7, name: 'Scored Sam', email: 'sam@red.test', role: 'user' };
    await telemetry.onLogin({ user, client: { ip: '10.0.0.1', userAgent: 'test' }, tokenHash: 'abc' });
    await telemetry.onAccess({ user, tokenHash: 'abc', client: {}, kind: 'page', id: 'dashboard', name: '/dashboard', action: 'read' });
    await telemetry.flush();
    await telemetry.runDay(new Date(Date.now() - 86400000).toISOString().slice(0, 10));
    assert.equal(calls.length, 0, 'not for a past day');
    await telemetry.runDay(today());
    assert.equal(calls.length, 1);
    assert.equal(calls[0].redUserId, 7);
    assert.ok(Number.isFinite(calls[0].result.finalScore));
  } finally {
    await crimguard.close();
  }
});

test('only admins reach the identity console, and without the risk database it all stands aside', async (t) => {
  const { app } = await withIdentity(t);
  const { b } = await app.signUp('Nosy Nora');
  assert.equal((await b('GET', '/api/admin/identity')).status, 403);
  assert.equal((await b('PATCH', '/api/admin/identity/policies/1', { isEnabled: false })).status, 403);

  const plain = await startApp();
  t.after(() => plain.close());
  const visitor = await plain.signUp('Plain Paula');
  assert.deepEqual((await visitor.b('GET', '/api/identity/status')).body, { frozen: false, stepUp: false });
  assert.equal((await visitor.b('POST', '/api/identity/step-up', { password: 'x' })).body.status, 'not_required');
  assert.equal((await visitor.b('GET', '/api/projects')).status, 200);
  assert.equal(createIdentity(null).enabled, false);
});
