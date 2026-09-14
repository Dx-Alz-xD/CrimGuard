'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { POLICY, targetTier, decide } = require('../src/honeytrap/policy');
const { LURES, chooseLure, canaryContext } = require('../src/honeytrap/lures');
const { KINDS, CANDIDATE_PATTERNS, generateCanary, extractCandidates, fingerprint } = require('../src/honeytrap/canaries');
const { createHoneytrap, FILE_ID_BASE } = require('../src/honeytrap/honeytrap');
const { TRAP_PATHS } = require('../src/honeytrap/routes');
const { createIdentity } = require('../src/identity/identity');
const { createStores } = require('../src/db');
const { connectCrimGuard } = require('../src/db/crimguard');
const { createSubjects } = require('../src/telemetry/subjects');
const { startApp, PASSWORD } = require('./helpers');

const DAY = 86400000;
const quiet = () => {};

// --- policy ------------------------------------------------------------------------------------------

test('the tier follows the score, and some scenarios raise it once a decoy is warranted', () => {
  assert.equal(targetTier(39, null), 0);
  assert.equal(targetTier(40, null), 1);
  assert.equal(targetTier(65, null), 2);
  assert.equal(targetTier(80, null), 3);
  assert.equal(targetTier(45, 'privilege_abuse'), 3, 'privilege abuse is shown privileged credentials');
  assert.equal(targetTier(30, 'privilege_abuse'), 0, 'but a scenario alone never plants');
  assert.equal(targetTier(null, 'credential_compromise'), 0);
});

test('the policy plants, holds, rotates, stands down and cools off', () => {
  const now = Date.parse('2026-09-14T12:00:00Z');
  const fresh = { id: 1, tier: 1, plantedAt: new Date(now - 2 * DAY).toISOString() };
  const stale = { id: 2, tier: 1, plantedAt: new Date(now - (POLICY.rotateAfterDays + 1) * DAY).toISOString() };

  assert.deepEqual(decide({ score: 50, active: [], now }), { tier: 1, plant: true, retire: [], coolingDown: false });
  assert.equal(decide({ score: 50, active: [fresh], now }).plant, false, 'one at this tier is enough');
  assert.equal(decide({ score: 70, active: [fresh], now }).plant, true, 'a higher tier adds a more valuable decoy');
  assert.equal(decide({ score: 90, active: [fresh, { ...fresh, id: 3, tier: 2 }], now }).plant, false, 'never more than maxActive');

  const held = decide({ score: 30, active: [fresh], now });
  assert.deepEqual([held.plant, held.retire], [false, []], 'between stand-down and plant, keep what is there');

  assert.deepEqual(decide({ score: 10, active: [fresh, stale], now }).retire.map((r) => r.reason), ['stood_down', 'stood_down']);
  assert.deepEqual(decide({ score: null, active: [fresh], now }).retire, [{ id: 1, reason: 'stood_down' }]);

  const rotated = decide({ score: 50, active: [stale], now });
  assert.deepEqual([rotated.retire, rotated.plant], [[{ id: 2, reason: 'rotated' }], true]);

  const cooling = decide({ score: 95, active: [], lastTripAt: new Date(now - 3600000).toISOString(), now });
  assert.deepEqual([cooling.plant, cooling.coolingDown], [false, true]);
});

// --- lures ---------------------------------------------------------------------------------------------

test('the decoy is the thing this person would reach for, and the reasons are kept', () => {
  const pick = (profile, tier) => chooseLure(profile, { tier, jitter: () => 0 });

  const hoarder = pick({ searchTerms: ['salary bands 2026', 'bonus pool'], scenario: 'pre_resignation_hoarding' }, 2);
  assert.equal(hoarder.lure.theme, 'compensation');
  assert.ok(hoarder.reasons.some((r) => r.includes('"salary"')), hoarder.reasons.join('; '));
  assert.ok(hoarder.reasons.some((r) => r.includes('pre resignation hoarding')));

  const admin = pick({ role: 'admin', scenario: 'privilege_abuse', topFeatures: ['admin_panel_access_flag'] }, 3);
  assert.equal(admin.lure.theme, 'break_glass');

  const aiLeak = pick({ scenario: 'shadow_ai_leak', searchTerms: ['github token for ci'], topFeatures: ['large_clipboard_copy_event_count'] }, 2);
  assert.equal(aiLeak.lure.theme, 'source_token');

  assert.ok(pick({ scenario: 'privilege_abuse' }, 1).lure.tier <= 1, 'the tier caps how valuable a decoy may be');
  assert.deepEqual(pick({}, 1).reasons.length > 0, true);

  const again = pick({ searchTerms: ['salary'], recentThemes: ['compensation'] }, 1);
  assert.notEqual(again.lure.theme, 'compensation', 'not the same decoy twice in a row');
  assert.equal(chooseLure({}, { tier: 1, exclude: LURES.filter((l) => l.tier === 1).map((l) => l.theme) }), null);
});

// --- canaries --------------------------------------------------------------------------------------------

test('every canary is found again in text, by the same expressions the browser runs', () => {
  const context = canaryContext(LURES[0], { orgName: 'Acme Corp', department: 'Finance' });
  for (const kind of Object.keys(KINDS)) {
    const a = generateCanary(kind, context);
    const b = generateCanary(kind, context);
    assert.notDeepEqual(a.values, b.values, `${kind}: fresh values per planting`);
    assert.equal(a.fingerprints.length, a.values.length);

    const pasted = `fyi see below\n${a.body}\nthanks`;
    const found = new Set(extractCandidates(pasted).map(fingerprint));
    for (const fp of a.fingerprints) assert.ok(found.has(fp), `${kind}: every value is recognised inside the file body`);
    for (const value of a.values) {
      assert.ok(extractCandidates(`copied: ${value} `).map(fingerprint).includes(fingerprint(value)), `${kind}: ${value} on its own`);
    }
  }

  const window = {};
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'static', 'shared-files.js'), 'utf8');
  vm.runInNewContext(source, { window, document: { body: { dataset: { page: 'test' } } } });
  // Array.from: arrays made inside the vm belong to another realm, which deepEqual tells apart.
  assert.deepEqual(Array.from(window.CrimGuardSharedFiles.CANDIDATE_PATTERNS, String), CANDIDATE_PATTERNS.map(String), 'browser and server patterns match');
  const sample = generateCanary('aws_access_key', context).body;
  assert.deepEqual(Array.from(window.CrimGuardSharedFiles.extractCandidates(sample)), extractCandidates(sample));

  assert.deepEqual(extractCandidates('short'), []);
  assert.equal(extractCandidates('x '.repeat(5000) + 'A'.repeat(26)).length, 1);
});

test('the browser never sends clipboard text, only matching fingerprints', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'static', 'shared-files.js'), 'utf8');
  const check = source.slice(source.indexOf('async function check('), source.indexOf("for (const type of ['copy', 'cut'])"));
  assert.match(check, /JSON\.stringify\(\{ action, fingerprints: matches \}\)/);
  assert.match(check, /watch\.has\(hash\.slice\(0, 8\)\)/);
  assert.ok(!/text[,}]/.test(check.slice(check.indexOf('JSON.stringify'))), 'the text itself is never in the request');
  assert.ok(!source.includes('honeytrap'), 'nothing in the page names the feature');
});

// --- the module against the risk database ---------------------------------------------------------------

// The real app with a risk database, its protection quiet and on no schedule.
async function startWithRisk(t, protection = {}) {
  const crimguard = await connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });
  const app = await startApp({
    crimguard, riskInterval: 0,
    protectionOptions: { log: quiet, honeytrapInterval: 0, ...protection, honeytrapOptions: { log: quiet, ...protection.honeytrapOptions } },
  });
  t.after(async () => {
    await app.server.telemetry.flush();
    app.close();
    await crimguard.close();
  });
  return { ...app, crimguard, stores: createStores(app.db) };
}

// A honeytrap of its own on a controllable clock, over the app's databases.
async function riskDb(t, options = {}) {
  const app = await startWithRisk(t);
  let clock = options.start ?? Date.parse('2026-09-14T12:00:00Z');
  const identity = createIdentity(app.crimguard, { stores: app.stores, log: quiet });
  const honeytrap = createHoneytrap(app.crimguard, { identity, log: quiet, jitter: () => 0, now: () => clock, ...options });
  const subjects = createSubjects(app.crimguard);
  let scored = 0;

  async function person(name, { jobTitle = null } = {}) {
    const { user } = await app.signUp(name);
    const crimId = await subjects.forUser(user);
    if (jobTitle) await app.crimguard.query('UPDATE users SET job_title = ? WHERE id = ?', [jobTitle, crimId]);
    return { user, crimId };
  }

  async function score(crimId, finalScore, { scenario = null, features = [] } = {}) {
    scored += 1;
    const date = new Date(clock).toISOString().slice(0, 10);
    const { rows: existing } = await app.crimguard.query('SELECT id FROM risk_feature_snapshot WHERE user_id = ? AND snapshot_date = ?', [crimId, date]);
    const snapshot = existing.length ? existing[0].id : (await app.crimguard.query(
      'INSERT INTO risk_feature_snapshot (user_id, snapshot_date, period_start, period_end) VALUES (?, ?, ?, ?) RETURNING id',
      [crimId, date, `${date}T00:00:00.000Z`, `${date}T23:59:59.000Z`],
    )).rows[0].id;
    const level = finalScore >= 80 ? 'critical' : finalScore >= 60 ? 'high' : finalScore >= 40 ? 'medium' : 'low';
    const payload = { contributions: features.map((feature, i) => ({ feature, points: 10 - i })) };
    await app.crimguard.query(
      `INSERT INTO risk_scores (snapshot_id, user_id, model_version, final_score, risk_level, scenario, dashboard_payload, scored_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [snapshot, crimId, `test-${scored}`, finalScore, level, scenario, JSON.stringify(payload), new Date(clock + scored).toISOString()],
    );
  }

  async function search(crimId, query) {
    await app.crimguard.query("INSERT INTO file_access_events (user_id, action, occurred_at, search_query) VALUES (?, 'search', ?, ?)",
      [crimId, new Date(clock - 3600000).toISOString(), query]);
  }

  return {
    app, honeytrap, person, score, search,
    advance: (ms) => { clock += ms; },
    q: (sql, params) => app.crimguard.query(sql, params).then((r) => r.rows),
  };
}

test('a decoy is planted for a risky person only, chosen from what they have been doing', async (t) => {
  const { honeytrap, person, score, search, q } = await riskDb(t);
  const suspect = await person('Sam', { jobTitle: 'Account Executive' });
  const bystander = await person('Bea');
  await search(suspect.crimId, 'customer contacts export');
  await score(suspect.crimId, 55, { scenario: 'pre_resignation_hoarding', features: ['files_accessed_count'] });
  await score(bystander.crimId, 12);

  const summary = await honeytrap.evaluateAll();
  assert.deepEqual([summary.people, summary.planted, summary.retired], [2, 1, 0]);
  const planted = summary.results.find((r) => r.crimUserId === suspect.crimId).planted;
  // Hoarding raises the tier to 2, but the searches point at customer data, a tier 1 decoy.
  assert.equal(planted.tier, 2);
  assert.equal(planted.theme, 'customer_export');
  assert.ok(planted.reasons.some((r) => r.includes('"customer"')));

  const files = await honeytrap.filesFor(suspect.user);
  assert.equal(files.length, 1);
  assert.equal(files[0].id, FILE_ID_BASE + planted.honeytokenId);
  assert.ok(Date.parse(files[0].updatedAt) <= Date.parse('2026-09-07T12:00:00Z'), 'looks like it has been there a while');
  assert.deepEqual(await honeytrap.filesFor(bystander.user), [], 'nobody else sees it');

  const [token] = await q('SELECT ht.token_type, ht.placement, r.is_honeytoken, r.sensitivity FROM honeytokens ht JOIN resources r ON r.id = ht.resource_id');
  assert.equal(token.token_type, 'canary_document');
  assert.equal(token.sensitivity, 'restricted');
  assert.equal(Boolean(token.is_honeytoken), true);
  assert.equal(JSON.parse(token.placement).planted.scenario, 'pre_resignation_hoarding');
  const [audit] = await q("SELECT action FROM platform_audit_log WHERE action LIKE 'honeytrap_%'");
  assert.equal(audit.action, 'honeytrap_planted');

  assert.equal((await honeytrap.evaluate(suspect.crimId)).planted, null, 'running again plants nothing more');
});

test('the watch list is the same for everyone and gives nothing away', async (t) => {
  const { honeytrap, person, score } = await riskDb(t);
  const suspect = await person('Sam');
  const bystander = await person('Bea');
  const before = await honeytrap.watchList(bystander.user);
  assert.equal(before.length, 12, 'padded even when nothing is armed');

  await score(suspect.crimId, 85, { scenario: 'credential_compromise' });
  await honeytrap.evaluate(suspect.crimId);
  const [planting] = await honeytrap.report(suspect.crimId).then((r) => r.plantings);
  const list = await honeytrap.watchList(suspect.user);
  assert.deepEqual(list, await honeytrap.watchList(bystander.user));
  const [row] = (await honeytrap.filesFor(suspect.user));
  const opened = await honeytrap.openFile({ user: suspect.user, fileId: row.id });
  for (const fp of extractCandidates(opened.file.body).map(fingerprint)) {
    if (list.includes(fp.slice(0, 8))) return assert.ok(planting.active);
  }
  assert.fail('the canary prefix is on the watch list');
});

test('rotation, stand-down and duplicate trips', async (t) => {
  const { honeytrap, person, score, advance, q } = await riskDb(t);
  const { user, crimId } = await person('Rae');
  await score(crimId, 45);
  const first = (await honeytrap.evaluate(crimId)).planted;

  advance((POLICY.rotateAfterDays + 1) * DAY);
  await score(crimId, 45);
  const rotated = await honeytrap.evaluate(crimId);
  assert.deepEqual(rotated.retired.map((r) => r.reason), ['rotated']);
  assert.ok(rotated.planted && rotated.planted.theme !== first.theme, 'a fresh, different decoy');

  // A canary from the rotated decoy is still armed.
  const oldBody = JSON.parse((await q('SELECT placement FROM honeytokens WHERE id = ?', [first.honeytokenId]))[0].placement).body;
  const reports = await honeytrap.inspectText({ user, text: `notes: ${oldBody}`, channel: 'project_description' });
  assert.equal(reports.length, 1);
  assert.equal(reports[0].interaction, 'exfiltrated');
  assert.deepEqual(await honeytrap.inspectText({ user, text: `again ${oldBody}` }), [], 'the same canary within the hour is one incident');
  assert.equal((await q('SELECT COUNT(*) AS n FROM honeytoken_triggers'))[0].n, 1);

  advance(DAY + 1);
  await score(crimId, 10);
  const stood = await honeytrap.evaluate(crimId);
  assert.deepEqual(stood.retired.map((r) => r.reason), ['stood_down']);
  assert.deepEqual(await honeytrap.filesFor(user), []);
});

test('without the risk database everything is a quiet no-op', async () => {
  const off = createHoneytrap(null);
  assert.throws(() => createHoneytrap({}), /identity throttle/, 'with one, a trap that can’t act on a trip is refused');
  assert.equal(off.enabled, false);
  assert.deepEqual(await off.filesFor({ id: 1 }), []);
  assert.deepEqual(await off.watchList(), []);
  assert.deepEqual(await off.sighting({ action: 'copy', fingerprints: ['a'.repeat(64)] }), []);
  assert.equal((await off.evaluateAll()).people, 0);
});

// --- over HTTP -------------------------------------------------------------------------------------------

async function withRoutes(t) {
  const trips = [];
  const app = await startWithRisk(t, { honeytrapOptions: { onTrip: (r) => trips.push(r) } });
  const { honeytrap } = app.server.protection;
  const subjects = createSubjects(app.crimguard);

  const { b, email, user: suspect } = await app.signUp('Sam Suspect');
  const colleagueAccount = await app.signUp('Cal Colleague');
  const crimId = await subjects.forUser(suspect);
  const colleagueCrimId = await subjects.forUser(colleagueAccount.user);

  const today = new Date().toISOString().slice(0, 10);
  const { rows } = await app.crimguard.query(
    'INSERT INTO risk_feature_snapshot (user_id, snapshot_date, period_start, period_end) VALUES (?, ?, ?, ?) RETURNING id',
    [crimId, today, `${today}T00:00:00.000Z`, `${today}T23:59:59.000Z`],
  );
  await app.crimguard.query(
    "INSERT INTO risk_scores (snapshot_id, user_id, model_version, final_score, risk_level, scenario) VALUES (?, ?, 'test', 72, 'high', 'shadow_ai_leak')",
    [rows[0].id, crimId],
  );
  await honeytrap.evaluate(crimId);

  const listed = await b('GET', '/api/files/shared');
  const file = listed.body.files[0];
  const opened = await b('GET', `/api/files/shared/${file.id}`);
  const canaries = extractCandidates(opened.body.file.body);
  const signIn = async (address) => {
    const other = app.browser();
    assert.equal((await other('POST', '/api/login', { email: address, password: PASSWORD, portal: 'user' })).status, 200);
    return other;
  };
  return { app, honeytrap, trips, b, email, suspect, colleagueAccount, listed, file, opened, canaries, crimId, colleagueCrimId, signIn };
}

const sessionsOf = (app, userId) => app.db.prepare('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?').get(userId).n;

test('the decoy looks like any shared file, and opening it is recorded but is not a trip', async (t) => {
  const { app, b, listed, file, opened, trips, crimId, colleagueAccount } = await withRoutes(t);
  assert.equal(listed.status, 200);
  assert.deepEqual(Object.keys(file).sort(), ['description', 'fileName', 'id', 'name', 'size', 'updatedAt']);
  assert.equal(listed.body.watch.length >= 12, true);
  assert.equal(opened.status, 200);
  assert.equal(trips.length, 0);
  assert.equal(JSON.stringify(listed.body).includes('honey'), false, 'nothing in the response names the trap');

  const { rows } = await app.crimguard.query("SELECT action, file_path FROM file_access_events WHERE user_id = ? AND action = 'read'", [crimId]);
  assert.deepEqual(rows, [{ action: 'read', file_path: file.fileName }]);

  const colleague = colleagueAccount.b;
  assert.deepEqual((await colleague('GET', '/api/files/shared')).body.files, []);
  assert.equal((await colleague('GET', `/api/files/shared/${file.id}`)).status, 404, 'someone else can’t open it by id');
  assert.equal((await b('GET', `/api/files/shared/${FILE_ID_BASE + 99999}`)).status, 404);
  assert.equal((await b('GET', '/api/files/shared')).status, 200, 'still signed in');
});

test('copying a canary freezes the account, ends every session and records the trip', async (t) => {
  const { app, b, email, suspect, canaries, trips, crimId, signIn } = await withRoutes(t);
  const otherDevice = await signIn(email);
  const suspectId = suspect.id;

  const noise = await b('POST', '/api/files/shared/integrity', { action: 'copy', fingerprints: [fingerprint('something else entirely')] });
  assert.equal(noise.status, 202, 'a fingerprint that is not a canary does nothing');
  assert.equal((await b('POST', '/api/files/shared/integrity', { action: 'copy', fingerprints: ['not-a-hash'] })).status, 202);

  const res = await b('POST', '/api/files/shared/integrity', { action: 'copy', fingerprints: canaries.map(fingerprint) });
  assert.equal(res.status, 401);
  assert.equal((await otherDevice('GET', '/api/files/shared')).status, 401, 'signed out everywhere');
  assert.equal(sessionsOf(app, suspectId), 0);

  assert.equal(trips.length, 1, 'one canary file, one incident, however many values matched');
  assert.deepEqual([trips[0].interaction, trips[0].via, trips[0].owner.crimUserId], ['copied', 'clipboard_copy', crimId]);

  const q = async (sql, params) => (await app.crimguard.query(sql, params)).rows;
  assert.equal((await q('SELECT interaction FROM honeytoken_triggers WHERE user_id = ?', [crimId]))[0].interaction, 'copied');
  const [freeze] = await q("SELECT status, request_payload FROM identity_actions WHERE user_id = ? AND action = 'session_freeze'", [crimId]);
  assert.deepEqual([freeze.status, freeze.request_payload.source], ['completed', 'honeytrap']);
  assert.equal(Boolean((await q('SELECT is_active FROM honeytokens'))[0].is_active), false, 'retired once tripped');
  assert.ok(app.stores.audit.list().some((e) => e.action === 'security.identity_session_freeze' && e.target_user_id === suspectId));
  const login = await app.browser()('POST', '/api/login', { email, password: PASSWORD, portal: 'user' });
  assert.deepEqual([login.status, login.body.code], [403, 'account_frozen'], 'signing back in waits for an admin');
});

test('a colleague pasting someone else’s canary is caught too, and so is its owner', async (t) => {
  const { app, canaries, trips, crimId, colleagueCrimId, colleagueAccount } = await withRoutes(t);
  const colleague = colleagueAccount.b;
  const res = await colleague('POST', '/api/files/shared/integrity', { action: 'paste', fingerprints: [fingerprint(canaries[0])] });
  assert.equal(res.status, 401);
  assert.equal(trips[0].presentedBy, colleagueCrimId);
  const { rows } = await app.crimguard.query('SELECT user_id FROM honeytoken_triggers ORDER BY user_id', []);
  assert.deepEqual(rows.map((r) => Number(r.user_id)).sort(), [crimId, colleagueCrimId].sort());
});

test('a leaked key tried against an API trips from anywhere, no session needed', async (t) => {
  const { app, canaries, trips, crimId } = await withRoutes(t);
  const stranger = app.browser();

  const miss = await stranger('GET', TRAP_PATHS[0], undefined, { authorization: 'Bearer ghp_notarealtokenatall000000000000000000' });
  assert.deepEqual([miss.status, miss.body.error, miss.headers.get('www-authenticate')], [401, 'Invalid credentials.', 'Bearer realm="internal"']);
  assert.equal(trips.length, 0);

  const key = canaries.find((c) => c.startsWith('ghp_') || c.startsWith('AKIA')) ?? canaries[0];
  const hit = await stranger('GET', TRAP_PATHS[1], undefined, { 'x-api-key': key });
  assert.equal(hit.status, 401, 'answers exactly like a miss');
  assert.equal(hit.body.error, miss.body.error);
  assert.equal(trips.length, 1);
  assert.deepEqual([trips[0].interaction, trips[0].via, trips[0].presentedBy], ['key_used', `api:${TRAP_PATHS[1]}`, null]);
  assert.equal(sessionsOf(app, trips[0].redUserIds[0]), 0, 'the owner is signed out');
  const [trigger] = (await app.crimguard.query('SELECT user_id FROM honeytoken_triggers', [])).rows;
  assert.equal(Number(trigger.user_id), crimId);
});

test('only admins see plantings or run the policy', async (t) => {
  const { app, b, crimId } = await withRoutes(t);
  assert.equal((await b('GET', `/api/admin/honeytrap/people/${crimId}`)).status, 403);
  assert.equal((await b('POST', '/api/admin/honeytrap/run', {})).status, 403);

  const admin = (await app.signInAdmin()).b;
  const report = await admin('GET', `/api/admin/honeytrap/people/${crimId}`);
  assert.equal(report.status, 200);
  assert.equal(report.body.plantings.length, 1);
  assert.equal(report.body.plantings[0].tier, 2);
  assert.ok(report.body.plantings[0].reasons.length > 0);
  const run = await admin('POST', '/api/admin/honeytrap/run', {});
  assert.deepEqual([run.status, run.body.planted], [200, 0]);
});

test('without the risk database the shared-files endpoints are empty and harmless', async (t) => {
  const app = await startApp();
  t.after(() => app.close());
  const { b } = await app.signUp('Nia');
  assert.deepEqual((await b('GET', '/api/files/shared')).body, { files: [], watch: [] });
  assert.equal((await b('POST', '/api/files/shared/integrity', { action: 'copy', fingerprints: ['a'.repeat(64)] })).status, 202);
  assert.equal((await app.browser()('GET', TRAP_PATHS[0])).status, 401);
});

test('a canary in a project description or an uploaded file is caught on the way in', async (t) => {
  const { app, b, canaries, trips } = await withRoutes(t);
  const secret = canaries[0];

  const project = await b('POST', '/api/projects', { name: 'Notes', description: 'nothing yet' });
  assert.equal(project.status, 201);
  const saved = await b('PATCH', `/api/projects/${project.body.project.id}`, { description: `for later: ${secret}` });
  assert.equal(saved.status, 401, 'the save is refused as signed out');
  assert.equal(trips.length, 1);
  assert.deepEqual([trips[0].interaction, trips[0].via], ['exfiltrated', 'project_text']);
  assert.equal(app.db.prepare('SELECT description FROM projects WHERE id = ?').get(project.body.project.id).description, 'nothing yet', 'and nothing was written');

  // The owner is frozen now; a colleague who got hold of the file and uploads it is caught as well.
  const colleague = await app.signUp('Una Uploader');
  const theirs = await colleague.b('POST', '/api/projects', { name: 'Stuff', description: '' });
  const upload = await fetch(`${app.base}/api/projects/${theirs.body.project.id}/files`, {
    method: 'POST',
    headers: { cookie: colleague.b.getCookie(), 'content-type': 'application/octet-stream', 'x-file-name': 'creds.txt' },
    body: `copied from the share\n${canaries.join('\n')}\n`,
  });
  assert.equal(upload.status, 401);
  assert.equal(trips.at(-1).via, 'project_file');
});
