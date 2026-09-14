'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { connectCrimGuard } = require('../src/db/crimguard');
const { createTelemetry } = require('../src/telemetry');
const { parseBatch } = require('../src/telemetry/ingest');
const { computeFeatures } = require('../src/telemetry/features');
const { coverage, assertCoversCatalog, summary } = require('../src/telemetry/coverage');
const { classifyText } = require('../src/telemetry/patterns');
const { isDecoyId, DECOY_ID_BASE } = require('../src/telemetry/honeytokens');
const { locate, travelBetween } = require('../src/telemetry/geo');
const { loadFeatureCatalog } = require('../crimguard/risk');
const { startApp, PASSWORD } = require('./helpers');

const today = () => new Date().toISOString().slice(0, 10);
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);
const memoryRisk = () => connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });

// An app with the risk database attached. The scheduled run is turned off so each test
// decides when aggregation happens.
async function startWithRisk(options = {}) {
  const crimguard = await memoryRisk();
  const app = await startApp({ crimguard, riskInterval: 0, ...options });
  const telemetry = app.server.telemetry;
  return {
    ...app,
    crimguard,
    telemetry,
    async close() {
      await telemetry.flush();
      app.close();
      await crimguard.close();
    },
  };
}

// --- the catalog and what Red collects of it ------------------------------------------

test('every variable in the catalog has a decided collection method', () => {
  const keys = loadFeatureCatalog().map((meta) => meta.key);
  assert.equal(keys.length, 100);
  assertCoversCatalog(keys); // throws if the two have drifted apart

  const counts = summary();
  assert.equal(counts.total, 100);
  assert.equal(counts.measured + counts.derived + counts['no-source'], 100);
  // Every entry needs a note explaining where the value comes from, or why there isn't one.
  for (const key of keys) assert.ok(coverage[key].note.length > 10, key);
});

test('variables with no source in a web app are left out entirely, never set to zero', () => {
  const window = { files: [], transfers: [], clipboard: [], endpoints: [], auth: [], biometrics: [], privilege: [], network: [], communication: [], sessions: [] };
  const subject = { person: {}, hrEvents: [], leave: [], projects: [] };
  const at = `${today()}T10:00:00.000Z`;
  const { features } = computeFeatures({
    date: today(),
    window: { ...window, files: [{ occurred_at: at, action: 'read', resource_id: 1, resource_type: 'file', sensitivity: 'internal', uri: 'red:project/1' }] },
    subject,
  });

  for (const [key, entry] of Object.entries(coverage)) {
    if (entry.collection === 'no-source') {
      assert.ok(features[key] === undefined || features[key] === null, `${key} should stay empty`);
    }
  }
  // A badge reader Red hasn't got must not look like "nobody entered the building".
  assert.equal(features.badge_restricted_area_access_count ?? null, null);
  assert.equal(features.usb_write_activity_count ?? null, null);
});

test('a day with no activity produces no snapshot, so baselines are built from days people used Red', () => {
  const empty = { files: [], transfers: [], clipboard: [], endpoints: [], auth: [], biometrics: [], privilege: [], network: [], communication: [], sessions: [] };
  const result = computeFeatures({ date: today(), window: empty, subject: { person: {}, hrEvents: [], leave: [], projects: [] } });
  assert.equal(result.active, false);
  assert.deepEqual(result.features, {});
});

// --- impossible travel --------------------------------------------------------------------

test('travel between two sign-ins is judged in km/h, not in hours of offset', () => {
  const at = (place, minutes) => ({ at: minutes * 60_000, location: locate({ timezone: place }) });
  const journey = (a, b, minutes) => travelBetween(at(a, 0), at(b, minutes));

  // A real flight is possible and must not be flagged.
  const flight = journey('Europe/Berlin', 'America/New_York', 600);
  assert.equal(flight.impossible, false);
  assert.ok(flight.speedKmh < 900, `${flight.speedKmh} km/h is a plane, not a teleport`);

  // The same journey in two hours is not.
  assert.equal(journey('Europe/Berlin', 'America/New_York', 120).impossible, true);

  // Paris and Lagos share a UTC offset and are 4,700 km apart. Comparing offsets misses this
  // entirely; comparing places does not.
  const sameOffset = journey('Europe/Paris', 'Africa/Lagos', 45);
  assert.equal(sameOffset.impossible, true);
  assert.ok(sameOffset.distanceKm > 4000);

  // Two sign-ins at the same instant from different cities: one of them is not where it says.
  assert.equal(journey('Europe/Berlin', 'Asia/Tokyo', 0).speedKmh, Infinity);
  assert.equal(journey('Europe/Berlin', 'Asia/Tokyo', 0).impossible, true);

  // Neighbours stay unflagged however fast the hop, because the distance is short.
  assert.equal(journey('Europe/Amsterdam', 'Europe/Brussels', 1).impossible, false);
  // And a time zone nobody can place is no location at all.
  assert.equal(travelBetween(at('Europe/Berlin', 0), { at: 1, location: locate({ timezone: 'Mars/Olympus' }) }), null);
});

test('impossible travel needs the network to have changed, so a VPN does not fire it', () => {
  const day = today();
  const login = (minutes, ip, zone) => {
    const place = locate({ timezone: zone });
    return {
      occurred_at: `${day}T${String(8 + Math.floor(minutes / 60)).padStart(2, '0')}:${String(minutes % 60).padStart(2, '0')}:00.000Z`,
      event_type: 'login_success',
      source_ip: ip,
      city: zone,
      country_code: place?.country ?? null,
      latitude: place?.latitude ?? null,
      longitude: place?.longitude ?? null,
      user_agent: 'Mozilla/5.0 (Windows NT 10.0)',
      device_id: 1,
    };
  };
  const empty = { files: [], transfers: [], clipboard: [], endpoints: [], biometrics: [], privilege: [], network: [], communication: [], sessions: [] };
  const run = (auth) => computeFeatures({
    date: day,
    window: { ...empty, auth },
    subject: { person: {}, hrEvents: [], leave: [], projects: [] },
  });

  // Berlin then Lagos, twenty minutes apart, from different networks.
  const jump = run([login(0, '203.0.113.5', 'Europe/Berlin'), login(20, '198.51.100.9', 'Africa/Lagos')]);
  assert.equal(jump.features.impossible_travel_flag, true);
  assert.ok(jump.travel.speedKmh > 900, 'and the console can say how fast that would have been');
  assert.ok(jump.travel.distanceKm > 4000);

  // The same two places from the same network is someone changing their machine's region,
  // not someone crossing a continent.
  const sameNetwork = run([login(0, '203.0.113.5', 'Europe/Berlin'), login(20, '203.0.113.5', 'Africa/Lagos')]);
  assert.equal(sameNetwork.features.impossible_travel_flag, false);

  // A different network but the same place is a VPN, which moves the address, not the person.
  const vpn = run([login(0, '203.0.113.5', 'Europe/Berlin'), login(20, '198.51.100.9', 'Europe/Berlin')]);
  assert.equal(vpn.features.impossible_travel_flag, false);
  assert.equal(vpn.features.unusual_ip_range_flag, true, 'though the new network is still noticed');

  // One sign-in cannot be a journey.
  assert.equal(run([login(0, '203.0.113.5', 'Europe/Berlin')]).features.impossible_travel_flag, false);
});

test('a network change mid-session is noticed, without pretending anyone signed in', () => {
  const day = today();
  const yesterday = daysAgo(1);
  const HOME = '81.2.69.142';
  const VPN = '185.220.101.55';

  const login = (date, ip) => ({
    occurred_at: `${date}T09:00:00.000Z`, event_type: 'login_success', source_ip: ip,
    city: 'Europe/London', country_code: 'GB', latitude: 51.51, longitude: -0.13,
    user_agent: 'Mozilla/5.0 (Windows NT 10.0)', device_id: 1,
  });
  const request = (date, hour, ip) => ({ occurred_at: `${date}T${hour}:00:00.000Z`, source_ip: ip, bytes_out: 50_000 });
  const empty = { files: [], transfers: [], clipboard: [], endpoints: [], biometrics: [], privilege: [], communication: [], sessions: [] };

  const run = (auth, network) => computeFeatures({
    date: day,
    window: { ...empty, auth, network },
    subject: { person: {}, hrEvents: [], leave: [], projects: [] },
    // Yesterday established the home network as this account's usual one.
    knownIps: ['81.2.69'],
  });

  // Signs in from home, then switches a VPN on. No second sign-in: only the address changes.
  const moved = run(
    [login(yesterday, HOME), login(day, HOME)],
    [request(day, '10', HOME), request(day, '11', HOME), request(day, '14', VPN), request(day, '15', VPN)],
  );
  assert.equal(moved.features.unusual_ip_range_flag, true, 'the move to a new network is the signal');
  assert.equal(moved.features.new_geolocation_login_flag, false, 'but nobody signed in from there');
  assert.equal(moved.features.impossible_travel_flag, false, 'and one sign-in is not a journey');

  // A day that never leaves the usual network sets nothing.
  const settled = run(
    [login(yesterday, HOME), login(day, HOME)],
    [request(day, '10', HOME), request(day, '15', HOME)],
  );
  assert.equal(settled.features.unusual_ip_range_flag, false);

  // A day with no addresses at all is not a day on an unusual network.
  assert.equal(run([], []).features.unusual_ip_range_flag ?? false, false);
});

// --- the browser collector's batches ----------------------------------------------------

test('a telemetry batch is clamped, and anything unrecognised is dropped rather than stored', () => {
  const now = Date.parse('2026-06-01T12:00:00.000Z');
  const batch = parseBatch({
    device: { fingerprint: 'f'.repeat(400), platform: 'Win32', timezone: 'Europe/Berlin', cores: 1e9 },
    windows: -5,
    samples: [
      { at: '2026-06-01T11:59:00.000Z', seconds: 60, keyIntervalMean: 140, mouseVelocityMean: -20, idleSeconds: 999999 },
      { seconds: 0 }, // no window length: dropped
      'nonsense',
    ],
    events: [
      { type: 'copy', at: '2026-06-01T11:59:30.000Z', chars: 4000, patterns: ['api_key', 'made_up'] },
      { type: 'print', at: '2026-06-01T11:59:40.000Z', pages: 3, sensitive: true },
      { type: 'exfiltrate_everything', at: '2026-06-01T11:59:50.000Z' }, // not a thing: dropped
    ],
  }, { now });

  assert.equal(batch.device.fingerprint.length, 128);
  assert.equal(batch.windows, 0);
  assert.equal(batch.samples.length, 1);
  assert.equal(batch.samples[0].mouseVelocityMeanPxS, 0, 'negative speeds are clamped, not stored');
  assert.equal(batch.samples[0].idleSeconds, 3600, 'idle time cannot exceed the longest window');

  assert.equal(batch.events.length, 2);
  assert.deepEqual(batch.events[0].patterns, ['api_key'], 'unknown pattern names are discarded');
  assert.equal(batch.events[1].eventType, 'print_job');
});

test('a batch timestamped in the past or the future is pulled back into the accepted window', () => {
  const now = Date.parse('2026-06-01T12:00:00.000Z');
  const { samples } = parseBatch({
    samples: [
      { at: '2020-01-01T00:00:00.000Z', seconds: 60 },
      { at: '2030-01-01T00:00:00.000Z', seconds: 60 },
    ],
  }, { now });
  assert.equal(samples[0].windowStart, '2026-06-01T06:00:00.000Z', 'six hours is as old as a batch may claim to be');
  assert.equal(samples[1].windowStart, '2026-06-01T12:05:00.000Z', 'and five minutes is as far ahead');
});

test('an oversized batch is refused outright', () => {
  assert.throws(() => parseBatch({ events: new Array(500).fill({ type: 'copy', chars: 1 }) }), /too large/i);
});

test('text is classified without the text itself being kept', () => {
  const found = classifyText('the salary spreadsheet, password: hunter2hunter2 and sk_live_abcdefghijklmnop1234');
  assert.ok(found.keywordHits >= 2);
  assert.ok(found.patterns.includes('api_key'));
  assert.ok(found.patterns.includes('password'));
  assert.equal(found.sensitivity, 'restricted');
  assert.equal(classifyText('a perfectly ordinary project about onboarding').patterns.length, 0);
});

// --- end to end through the website -------------------------------------------------------

test('using Red fills in the risk variables, and the score is explainable', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, user } = await app.signUp('Tess Telemetry');
  for (let i = 0; i < 6; i++) {
    assert.equal((await b('POST', '/api/projects', { name: `Project ${i}`, description: 'Ordinary work' })).status, 201);
  }
  assert.equal((await b('GET', '/api/projects')).status, 200);
  assert.equal((await b('GET', '/api/projects/export')).status, 200);

  // The behaviour only a browser can see.
  const sent = await b('POST', '/api/telemetry', {
    device: { fingerprint: 'test-fingerprint', platform: 'Win32', timezone: 'Europe/Berlin' },
    windows: 2,
    samples: [{ at: new Date().toISOString(), seconds: 300, keyIntervalMean: 150, keyIntervalStd: 60, mouseVelocityMean: 600, scrollEvents: 20, appSwitches: 4, idleSeconds: 30, windows: 2, copyPaste: 3 }],
    events: [{ type: 'copy', at: new Date().toISOString(), chars: 9000, patterns: ['api_key'] }, { type: 'print', at: new Date().toISOString(), pages: 5 }],
  });
  assert.equal(sent.status, 202);
  assert.equal(sent.body.accepted, 3);

  const report = await b('GET', '/api/me/risk');
  assert.equal(report.status, 200);
  assert.equal(report.body.features.length, 100, 'the panel is shown every variable, valued or not');

  const byKey = Object.fromEntries(report.body.features.map((feature) => [feature.key, feature]));
  assert.equal(byKey.files_accessed_count.value > 0, true);
  assert.equal(byKey.daily_download_volume_mb.value > 0, true, 'the export is data leaving');
  assert.equal(byKey.large_clipboard_copy_event_count.value, 1);
  assert.equal(byKey.print_job_volume.value, 5);
  assert.equal(byKey.copy_paste_frequency_volume.value, 1);
  assert.equal(byKey.open_app_window_count.value, 2);
  assert.equal(byKey.credential_sharing_in_chat_flag.value, true, 'a key-shaped copy is a credential signal');
  assert.equal(byKey.tenure_months.value, 0);
  assert.equal(byKey.badge_restricted_area_access_count.value, null, 'no badge system, so no number');
  assert.equal(byKey.badge_restricted_area_access_count.collection, 'no-source');

  // Every variable carries where it came from, which is what makes a blank readable.
  for (const feature of report.body.features) {
    assert.ok(['measured', 'derived', 'no-source'].includes(feature.collection), feature.key);
  }
  assert.equal(report.body.coverage.total, 100);
  void user;
});

test("one account cannot see another account's risk assessment", async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const alice = await app.signUp('Alice');
  const bob = await app.signUp('Bob');
  await alice.b('GET', '/api/projects');
  await bob.b('GET', '/api/projects');
  await app.telemetry.flush();

  // /api/me/risk takes the account from the session, so there is nothing to point elsewhere.
  const mine = await alice.b('GET', '/api/me/risk');
  assert.equal(mine.status, 200);

  // The console that can see everyone is admin-only.
  assert.equal((await alice.b('GET', '/api/admin/risk/overview')).status, 403);
  assert.equal((await bob.b('GET', `/api/admin/risk/people/1`)).status, 403);
  assert.equal((await app.browser()('GET', '/api/me/risk')).status, 401);
});

test('an admin sees everyone, and can record the HR context the amplifier runs on', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b: userB } = await app.signUp('Watched Person');
  await userB('GET', '/api/projects');
  const admin = await app.signInAdmin();
  await app.telemetry.flush();
  await app.telemetry.runDay(today());

  const overview = await admin.b('GET', '/api/admin/risk/overview');
  assert.equal(overview.status, 200);
  assert.ok(overview.body.people.length >= 2);
  assert.equal(overview.body.coverage.total, 100);

  const person = overview.body.people.find((row) => row.name === 'Watched Person');
  assert.ok(person, 'the person shows up in the console');

  const hr = await admin.b('PATCH', `/api/admin/risk/people/${person.id}`, {
    employmentType: 'contractor', hireDate: '2026-01-05', terminationDate: daysAgo(-14),
  });
  assert.equal(hr.status, 200, JSON.stringify(hr.body));

  // A leaving date before the hire date is refused rather than stored.
  assert.equal((await admin.b('PATCH', `/api/admin/risk/people/${person.id}`, { hireDate: '2026-01-05', terminationDate: '2025-01-01' })).status, 400);
  assert.equal((await admin.b('PATCH', `/api/admin/risk/people/${person.id}`, { employmentType: 'wizard' })).status, 400);
  assert.equal((await admin.b('POST', `/api/admin/risk/people/${person.id}/hr-events`, { type: 'not_a_thing', effectiveDate: today() })).status, 400);

  assert.equal((await admin.b('POST', `/api/admin/risk/people/${person.id}/hr-events`, {
    type: 'performance_review', effectiveDate: daysAgo(10), isNegative: true,
  })).status, 201);

  await app.telemetry.runDay(today());
  const detail = await admin.b('GET', `/api/admin/risk/people/${person.id}`);
  assert.equal(detail.status, 200);
  const byKey = Object.fromEntries(detail.body.features.map((feature) => [feature.key, feature.value]));
  assert.equal(byKey.employment_type, 'contractor');
  assert.equal(byKey.recent_negative_review_flag, true);
  assert.ok(byKey.termination_date_on_file, 'a leaving date on file is what the amplifier ramps on');
  assert.ok(Number(detail.body.score.hr_amplifier) > 1, 'and it raises the amplifier above 1');
});

test('a role change in Red becomes the privilege events and the role assignment the ledger reads', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { user } = await app.signUp('Promoted Pat');
  const admin = await app.signInAdmin();
  assert.equal((await admin.b('PATCH', `/api/admin/users/${user.id}/role`, { role: 'admin' })).status, 200);
  await app.telemetry.flush();
  await app.telemetry.runDay(today());

  const { rows } = await app.crimguard.query(
    `SELECT event_type FROM privilege_events WHERE occurred_at >= ? ORDER BY event_type`,
    [`${today()}T00:00:00.000Z`],
  );
  const kinds = new Set(rows.map((row) => row.event_type));
  assert.ok(kinds.has('permission_change'));
  assert.ok(kinds.has('sensitive_group_membership_change'));
  assert.ok(kinds.has('new_system_access_granted'));

  const { rows: assignments } = await app.crimguard.query('SELECT source FROM user_role_assignments WHERE valid_to IS NULL');
  assert.ok(assignments.length >= 1, 'the promotion is on the role timeline');

  // The admin who did it has the privilege signals against their own name.
  const overview = await admin.b('GET', '/api/admin/risk/overview');
  const actor = overview.body.people.find((row) => row.email === 'ada@red.test');
  const detail = await admin.b('GET', `/api/admin/risk/people/${actor.id}`);
  const byKey = Object.fromEntries(detail.body.features.map((feature) => [feature.key, feature.value]));
  assert.equal(byKey.permission_change_count >= 1, true);
  assert.equal(byKey.sensitive_group_membership_change_flag, true);
  assert.equal(byKey.no_ticket_new_system_access_flag, true, 'granted with no ticket to justify it');
});

test('reaching past your role is recorded even though the request is refused', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, user } = await app.signUp('Curious');
  assert.equal((await b('GET', '/api/admin/users')).status, 403);
  assert.equal((await b('GET', '/api/admin/audit')).status, 403);
  await app.telemetry.flush();
  await app.telemetry.runDay(today());

  const admin = await app.signInAdmin();
  const overview = await admin.b('GET', '/api/admin/risk/overview');
  const person = overview.body.people.find((row) => row.redUserId === user.id);
  const detail = await admin.b('GET', `/api/admin/risk/people/${person.id}`);
  const byKey = Object.fromEntries(detail.body.features.map((feature) => [feature.key, feature.value]));

  assert.equal(byKey.least_privilege_violation_flag, true);
  assert.equal(byKey.out_of_scope_resource_access_count, 2);
});

// --- honeytokens -----------------------------------------------------------------------------

test('a decoy appears once the score crosses the threshold, and only for that account', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, user } = await app.signUp('Baited');
  const other = await app.signUp('Uninvolved');
  await b('GET', '/api/projects');
  await app.telemetry.flush();

  // Below the threshold there is nothing to find.
  assert.equal((await app.telemetry.honeytokens.listFor(user.id)).length, 0);
  assert.equal((await b('GET', '/api/projects')).body.projects.length, 0);

  await app.telemetry.honeytokens.plantIfNeeded(user.id, 95);
  const listed = (await b('GET', '/api/projects')).body.projects;
  assert.equal(listed.length, 1, 'the decoy sits in the list like any other project');
  assert.ok(isDecoyId(listed[0].id));
  assert.ok(/key|payroll|customer|credential/i.test(listed[0].name), 'and is named like something worth taking');

  // It belongs to one account. Nobody else sees it, and planting twice does not stack.
  assert.equal((await other.b('GET', '/api/projects')).body.projects.length, 0);
  assert.equal(await app.telemetry.honeytokens.plantIfNeeded(user.id, 99), null);
  assert.equal((await b('GET', '/api/projects')).body.projects.length, 1);
});

test('changing a decoy revokes every session and is recorded as a honeytoken trip', async (t) => {
  const tripped = [];
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, email, user } = await app.signUp('Took The Bait');
  await b('GET', '/api/projects');
  await app.telemetry.flush();
  await app.telemetry.honeytokens.plantIfNeeded(user.id, 95);

  // Signed in on a second device, to check the revocation reaches everywhere.
  const phone = app.browser();
  assert.equal((await phone('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200);

  const decoy = (await b('GET', '/api/projects')).body.projects[0];
  const attempt = await b('PATCH', `/api/projects/${decoy.id}`, { name: 'mine now' });
  assert.equal(attempt.status, 401, 'the request is refused as signed-out, which sends the browser to the login page');

  assert.equal((await b('GET', '/api/me')).status, 401, 'this session is gone');
  assert.equal((await phone('GET', '/api/me')).status, 401, 'and so is every other one');
  assert.equal((await app.browser()('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200,
    'the account still exists: the sessions were revoked, not the person');

  const { rows } = await app.crimguard.query('SELECT interaction, user_id FROM honeytoken_triggers');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].interaction, 'modified');

  const { rows: actions } = await app.crimguard.query("SELECT action, status FROM identity_actions WHERE action = 'session_revoke'");
  assert.equal(actions.length, 1);
  assert.equal(actions[0].status, 'completed');

  // The decoy is spent, so it cannot collect the same trip twice.
  const { rows: tokens } = await app.crimguard.query('SELECT is_active FROM honeytokens');
  assert.equal(tokens[0].is_active, false);
  void tripped;
});

test('a honeytoken trip floors the next risk score at critical', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, user } = await app.signUp('Floored');
  await b('GET', '/api/projects');
  await b('POST', '/api/projects', { name: 'Ordinary', description: 'nothing to see' });
  await app.telemetry.flush();
  await app.telemetry.honeytokens.plantIfNeeded(user.id, 95);

  const decoy = (await b('GET', '/api/projects')).body.projects.find((project) => isDecoyId(project.id));
  await b('DELETE', `/api/projects/${decoy.id}`);
  await app.telemetry.flush();
  await app.telemetry.runDay(today());

  const admin = await app.signInAdmin();
  const overview = await admin.b('GET', '/api/admin/risk/overview');
  const person = overview.body.people.find((row) => row.redUserId === user.id);
  assert.equal(person.level, 'critical');
  assert.equal(person.score, 100);
  assert.equal(person.scenario, 'honeytoken_trip');

  const { rows } = await app.crimguard.query("SELECT interaction FROM honeytoken_triggers");
  assert.equal(rows[0].interaction, 'deleted');
});

test('a fresh decoy is planted after one is tripped, and it is a different one', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, email, user } = await app.signUp('Repeat Offender');
  await b('GET', '/api/projects');
  await app.telemetry.flush();

  await app.telemetry.honeytokens.plantIfNeeded(user.id, 95);
  const first = (await app.telemetry.honeytokens.listFor(user.id))[0];
  await b('PATCH', `/api/projects/${first.id}`, { name: 'x' });
  await app.telemetry.flush();
  assert.deepEqual(await app.telemetry.honeytokens.listFor(user.id), [], 'the tripped decoy is retired');

  // Still above the threshold after signing back in, so a new decoy goes down. The retired
  // one must not block it.
  const again = app.browser();
  assert.equal((await again('POST', '/api/login', { email, password: PASSWORD, portal: 'user' })).status, 200);
  const planted = await app.telemetry.honeytokens.plantIfNeeded(user.id, 95);
  assert.ok(planted, 'a second decoy is planted');
  assert.notEqual(planted.project.name, first.name, 'and it is not the same name sitting there again');

  const listed = (await again('GET', '/api/projects')).body.projects;
  assert.equal(listed.length, 1);
  assert.equal(listed[0].name, planted.project.name);
  assert.notEqual(listed[0].id, first.id, 'a new decoy, not the old id revived');
});

test('a decoy id that was never planted is just a missing project', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b } = await app.signUp('Nothing Planted');
  const res = await b('PATCH', `/api/projects/${DECOY_ID_BASE + 4242}`, { name: 'x' });
  assert.equal(res.status, 404);
  assert.equal((await b('GET', '/api/me')).status, 200, 'and the session is untouched');
});

// --- the test-value override (temporary) -----------------------------------------------------

test('an admin can force a score, which is what drives limiting', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, user } = await app.signUp('Vera');
  await b('GET', '/api/projects');
  // Limiting measures down from the average confidentiality of the files here, so there has to
  // be at least one file for there to be an average at all.
  const project = (await b('POST', '/api/projects', { name: 'Something to measure' })).body.project;
  await fetch(`${app.base}/api/projects/${project.id}/files`, {
    method: 'POST',
    headers: { cookie: b.getCookie(), 'content-type': 'application/octet-stream', 'x-file-name': 'notes.txt' },
    body: Buffer.from('x'),
  });
  await app.telemetry.flush();
  const admin = await app.signInAdmin();
  const url = `/api/crimguard/people/${user.id}/override`;

  const forced = await admin.b('PUT', url, { score: 88 });
  assert.equal(forced.status, 200, JSON.stringify(forced.body));
  assert.equal(forced.body.forced, true);
  assert.equal(forced.body.score, 88);
  assert.equal(forced.body.level, 'high');

  // The score reaches red.db, which is where file visibility reads it from.
  assert.equal(app.db.prepare('SELECT score FROM user_risk_state WHERE user_id = ?').get(user.id).score, 88);
  assert.equal(forced.body.limit.tier, 'tightened');

  // Back down again, and the limit lifts.
  const calm = await admin.b('PUT', url, { score: 10 });
  assert.equal(calm.body.limit.tier, null);
  assert.equal(calm.body.limit.limited, false);
});

test('with no files there is no average, so a high score limits nothing', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, user } = await app.signUp('Vaughn');
  await b('GET', '/api/projects');
  await app.telemetry.flush();
  const admin = await app.signInAdmin();

  const forced = await admin.b('PUT', `/api/crimguard/people/${user.id}/override`, { score: 99 });
  assert.equal(forced.body.score, 99);
  assert.equal(forced.body.limit.baseline, null);
  assert.equal(forced.body.limit.tier, null, 'nothing to measure a cut against');
  assert.equal(forced.body.limit.limited, false);
});

test('setting variables leaves the engine to score them, and stores what was set', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, user } = await app.signUp('Val');
  await b('GET', '/api/projects');
  await app.telemetry.flush();
  const admin = await app.signInAdmin();
  const url = `/api/crimguard/people/${user.id}/override`;

  const set = await admin.b('PUT', url, {
    features: { files_accessed_count: 400, bulk_directory_access_flag: true, daily_download_volume_mb: 250.5 },
  });
  assert.equal(set.status, 200, JSON.stringify(set.body));
  assert.equal(set.body.forced, false, 'with no score given, the real engine runs');

  const { variables } = (await admin.b('GET', `/api/crimguard/people/${user.id}/variables`)).body;
  const byKey = Object.fromEntries(variables.map((feature) => [feature.key, feature.value]));
  assert.equal(byKey.files_accessed_count, 400);
  assert.equal(byKey.bulk_directory_access_flag, true);
  assert.equal(byKey.daily_download_volume_mb, 250.5);

  // Setting one variable leaves the others alone.
  await admin.b('PUT', url, { features: { files_accessed_count: 7 } });
  const after = Object.fromEntries((await admin.b('GET', `/api/crimguard/people/${user.id}/variables`)).body
    .variables.map((feature) => [feature.key, feature.value]));
  assert.equal(after.files_accessed_count, 7);
  assert.equal(after.bulk_directory_access_flag, true, 'untouched variables survive');

  // Clearing one sets it back to not collected.
  await admin.b('PUT', url, { features: { bulk_directory_access_flag: null } });
  const cleared = Object.fromEntries((await admin.b('GET', `/api/crimguard/people/${user.id}/variables`)).body
    .variables.map((feature) => [feature.key, feature.value]));
  assert.equal(cleared.bulk_directory_access_flag, null);
});

test('the override checks what it is given, and is admins only', async (t) => {
  const app = await startWithRisk();
  t.after(() => app.close());

  const { b, user } = await app.signUp('Vic');
  await b('GET', '/api/projects');
  await app.telemetry.flush();
  const admin = await app.signInAdmin();
  const url = `/api/crimguard/people/${user.id}/override`;

  assert.equal((await admin.b('PUT', url, { score: 500 })).status, 400);
  assert.equal((await admin.b('PUT', url, { score: -1 })).status, 400);
  assert.equal((await admin.b('PUT', url, { features: { not_a_variable: 1 } })).status, 400);
  assert.equal((await admin.b('PUT', url, { features: { files_accessed_count: 'lots' } })).status, 400);
  assert.equal((await admin.b('PUT', url, { features: { files_accessed_count: -4 } })).status, 400);
  assert.equal((await admin.b('PUT', url, { features: { bulk_directory_access_flag: 'maybe' } })).status, 400);
  assert.equal((await admin.b('PUT', url, { date: 'yesterday' })).status, 400);
  assert.equal((await admin.b('PUT', '/api/crimguard/people/999999/override', { score: 50 })).status, 404);

  // Not something an ordinary account can reach.
  assert.equal((await b('PUT', url, { score: 0 })).status, 403);
  assert.equal((await b('GET', `/api/crimguard/people/${user.id}/variables`)).status, 403);
});

// --- the website still works without the risk database ------------------------------------

test('with no risk database attached, Red behaves exactly as before', async (t) => {
  const app = await startApp(); // no crimguard
  t.after(() => app.close());

  const { b } = await app.signUp('Unmonitored');
  assert.equal((await b('POST', '/api/projects', { name: 'Still works' })).status, 201);
  assert.equal((await b('GET', '/api/projects')).body.projects.length, 1);
  assert.equal((await b('GET', '/api/projects/export')).status, 200);
  assert.equal((await b('POST', '/api/telemetry', { samples: [], events: [] })).status, 202, 'batches are accepted and discarded');
  assert.equal((await b('GET', '/api/me/risk')).status, 503, 'and the panel is told why there is nothing to show');
});
