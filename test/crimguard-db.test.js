'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { buildSqliteSchema } = require('../src/db/sqlite-schema');
const { connectCrimGuard } = require('../src/db/crimguard');

const memoryDb = () => connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });
const columnsOf = async (db, name) => (await db.query('SELECT name FROM pragma_table_info(?)', [name])).rows.map((r) => r.name);

// Rejects with a constraint error rather than some unrelated failure.
const rejectsConstraint = (promise) => assert.rejects(promise, /constraint failed/i);

async function seedOrg(db) {
  const [{ id: orgId }] = (await db.query("INSERT INTO organizations (name, industry) VALUES ('Acme Health', 'healthcare') RETURNING id")).rows;
  const addUser = async (email, name, type) =>
    (await db.query('INSERT INTO users (org_id, email, full_name, employment_type) VALUES (?, ?, ?, ?) RETURNING id', [orgId, email, name, type])).rows[0].id;
  return { orgId, alice: await addUser('alice@acme.test', 'Alice DBA', 'full_time'), bob: await addUser('bob@acme.test', 'Bob Analyst', 'contractor') };
}

test('the SQLite schema has every table, column, view and all 100 risk variables', async () => {
  const db = await memoryDb();
  const { tables } = buildSqliteSchema();
  const objects = (await db.query("SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")).rows;

  assert.equal(tables.length, 56);
  assert.equal(objects.filter((o) => o.type === 'table').length, 56);
  assert.deepEqual(objects.filter((o) => o.type === 'view').map((o) => o.name).sort(), ['v_active_user_context', 'v_risk_feature_vector', 'v_shadow_ai_activity']);
  for (const table of tables) assert.deepEqual(await columnsOf(db, table.name), table.columns.map((c) => c.name), table.name);

  const catalog = (await db.query('SELECT feature_key FROM feature_catalog ORDER BY feature_key')).rows.map((r) => r.feature_key);
  const featureColumns = [];
  for (const { name } of tables.filter((t) => t.name.startsWith('feat_'))) {
    featureColumns.push(...(await columnsOf(db, name)).filter((c) => c !== 'snapshot_id' && c !== 'computed_at'));
  }
  assert.equal(catalog.length, 100);
  assert.deepEqual(featureColumns.sort(), catalog);
  assert.deepEqual((await columnsOf(db, 'v_risk_feature_vector')).slice(4).sort(), catalog);
  await db.close();
});

test('each column name means the same type in every table, so rows convert consistently', async () => {
  const db = await memoryDb();
  const typesByName = new Map();
  const { rows } = await db.query("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'");
  for (const { name: table } of rows) {
    for (const { name, type } of (await db.query('SELECT name, type FROM pragma_table_info(?)', [table])).rows) {
      const kind = ['BOOLEAN', 'JSONB'].includes(type) ? type : 'other';
      typesByName.set(name, (typesByName.get(name) || new Set()).add(kind));
    }
  }
  const mixed = [...typesByName].filter(([, kinds]) => kinds.size > 1).map(([name]) => name);
  assert.deepEqual(mixed, []);
  await db.close();
});

test('falls back to SQLite when PostgreSQL is not configured or not reachable, and builds the file if missing', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'crimguard-'));
  const sqlitePath = path.join(dir, 'crimguard.db');
  const unreachable = 'postgres://someone:secret-pass@127.0.0.1:1/crimguard';
  try {
    const noUrl = await connectCrimGuard({ mode: 'auto', databaseUrl: '', sqlitePath });
    assert.equal(noUrl.dialect, 'sqlite');
    assert.match(noUrl.fallbackReason, /CRIMGUARD_DATABASE_URL is not set/);
    assert.equal((await noUrl.query('SELECT count(*) AS n FROM feature_catalog')).rows[0].n, 100);
    await noUrl.close();
    assert.ok(fs.existsSync(sqlitePath));
    assert.ok(!fs.existsSync(`${sqlitePath}.tmp`));

    const down = await connectCrimGuard({ mode: 'auto', databaseUrl: unreachable, sqlitePath });
    assert.equal(down.dialect, 'sqlite');
    assert.match(down.fallbackReason, /PostgreSQL/);
    assert.doesNotMatch(down.fallbackReason, /secret-pass/);
    await down.close();

    await assert.rejects(connectCrimGuard({ mode: 'postgres', databaseUrl: unreachable, sqlitePath }), /PostgreSQL/);
    await assert.rejects(connectCrimGuard({ mode: 'mysql', sqlitePath }), /CRIMGUARD_DB must be one of/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SQLite returns booleans, arrays, JSON and ISO timestamps like PostgreSQL does (Case A vs Case B)', async () => {
  const db = await memoryDb();
  const { orgId, alice, bob } = await seedOrg(db);

  const [{ id: dba }] = (await db.query("INSERT INTO roles (org_id, name) VALUES (?, 'DBA') RETURNING id", [orgId])).rows;
  await db.query("INSERT INTO user_role_assignments (user_id, role_id, valid_from) VALUES (?, ?, '2021-01-10')", [alice, dba]);
  const [{ id: ticket }] = (await db.query(
    `INSERT INTO tickets (org_id, external_key, title, status, expected_daily_file_volume, opened_at)
     VALUES (?, 'DBM-142', 'Migrate patient-records DB', 'in_progress', 600, ?) RETURNING id`,
    [orgId, new Date('2026-09-01T09:00:00Z')],
  )).rows;
  await db.query('INSERT INTO ticket_assignments (ticket_id, user_id, assigned_at) VALUES (?, ?, ?)', [ticket, alice, new Date('2026-09-01T09:00:00Z')]);

  for (const [user, files, bulk] of [[alice, 650, true], [bob, 70, false]]) {
    const [{ id: snapshot }] = (await db.query(
      "INSERT INTO risk_feature_snapshot (user_id, snapshot_date, period_start, period_end) VALUES (?, '2026-09-13', ?, ?) RETURNING id",
      [user, new Date('2026-09-13T00:00:00Z'), new Date('2026-09-14T00:00:00Z')],
    )).rows;
    await db.query('INSERT INTO feat_access_resource (snapshot_id, files_accessed_count, bulk_directory_access_flag) VALUES (?, ?, ?)', [snapshot, files, bulk]);
  }

  const vector = (await db.query('SELECT user_id, files_accessed_count, bulk_directory_access_flag, usb_write_activity_count, snapshot_date FROM v_risk_feature_vector ORDER BY user_id')).rows;
  assert.deepEqual(vector, [
    { user_id: alice, files_accessed_count: 650, bulk_directory_access_flag: true, usb_write_activity_count: null, snapshot_date: '2026-09-13' },
    { user_id: bob, files_accessed_count: 70, bulk_directory_access_flag: false, usb_write_activity_count: null, snapshot_date: '2026-09-13' },
  ]);

  const context = (await db.query('SELECT user_id, current_roles, active_ticket_keys, active_ticket_count, max_expected_daily_file_volume, on_leave_today FROM v_active_user_context ORDER BY user_id')).rows;
  assert.deepEqual(context, [
    { user_id: alice, current_roles: ['DBA'], active_ticket_keys: ['DBM-142'], active_ticket_count: 1, max_expected_daily_file_volume: 600, on_leave_today: false },
    { user_id: bob, current_roles: null, active_ticket_keys: null, active_ticket_count: 0, max_expected_daily_file_volume: null, on_leave_today: false },
  ]);

  const [{ id: domain }] = (await db.query("INSERT INTO external_domains (domain, category) VALUES ('chat.example-llm.ai', 'genai_llm') RETURNING id")).rows;
  const [event] = (await db.query(
    "INSERT INTO clipboard_events (user_id, external_domain_id, occurred_at, char_count, detected_patterns, enforcement) VALUES (?, ?, ?, 18000, ?, 'blocked') RETURNING detected_patterns, occurred_at",
    [bob, domain, new Date('2026-09-13T15:30:00Z'), ['api_key', 'source_code']],
  )).rows;
  assert.deepEqual(event, { detected_patterns: ['api_key', 'source_code'], occurred_at: '2026-09-13T15:30:00.000Z' });
  assert.equal((await db.query('SELECT count(*) AS n FROM v_shadow_ai_activity')).rows[0].n, 1);

  const [edr] = (await db.query("INSERT INTO edr_alerts (org_id, vendor, external_id, severity, title, occurred_at, raw) VALUES (?, 'defender', 'x1', 'high', 't', ?, ?) RETURNING raw", [orgId, new Date(), { rule: 'T1048', hits: 3 }])).rows;
  assert.deepEqual(edr.raw, { rule: 'T1048', hits: 3 });

  assert.equal((await db.query("UPDATE users SET job_title = 'Lead', updated_at = '2000-01-01T00:00:00.000Z' WHERE org_id = ?", [orgId])).rowCount, 2);
  const [{ updated_at: updatedAt }] = (await db.query('SELECT updated_at FROM users WHERE id = ?', [alice])).rows;
  assert.notEqual(updatedAt, '2000-01-01T00:00:00.000Z', 'the updated_at trigger overrides manual values, as in PostgreSQL');
  await db.close();
});

test('SQLite enforces the same constraints as PostgreSQL', async () => {
  const db = await memoryDb();
  const { orgId, alice } = await seedOrg(db);
  const [{ id: snapshot }] = (await db.query("INSERT INTO risk_feature_snapshot (user_id, snapshot_date, period_start, period_end) VALUES (?, '2026-09-13', '2026-09-13T00:00:00Z', '2026-09-14T00:00:00Z') RETURNING id", [alice])).rows;

  await rejectsConstraint(db.query('INSERT INTO feat_data_movement (snapshot_id, usb_write_activity_count) VALUES (?, -1)', [snapshot]));
  await rejectsConstraint(db.query('INSERT INTO feat_temporal (snapshot_id, after_hours_access_frequency) VALUES (?, 1.5)', [snapshot]));
  await rejectsConstraint(db.query('INSERT INTO feat_temporal (snapshot_id, burst_activity_flag) VALUES (?, 2)', [snapshot]));
  await rejectsConstraint(db.query("UPDATE users SET employment_type = 'intern' WHERE id = ?", [alice]));
  await rejectsConstraint(db.query("INSERT INTO risk_feature_snapshot (user_id, snapshot_date, period_start, period_end) VALUES (?, '2026-09-13', '2026-09-13T00:00:00Z', '2026-09-14T00:00:00Z')", [alice]));
  await rejectsConstraint(db.query("INSERT INTO users (org_id, email, full_name) VALUES (999, 'ghost@acme.test', 'Ghost')"));
  await rejectsConstraint(db.query("INSERT INTO feature_baselines (feature_key, window_type, user_id, role_id, period_start, period_end, sample_count) VALUES ('files_accessed_count', 'peer_group', ?, 1, '2026-01-01', '2026-01-31', 5)", [alice]));
  await rejectsConstraint(db.query("INSERT INTO edr_alerts (org_id, vendor, external_id, severity, title, occurred_at, raw) VALUES (?, 'v', 'x', 'high', 't', '2026-09-13T00:00:00Z', 'not json')", [orgId]));

  // NULL org_id means a global entry, and PostgreSQL's UNIQUE NULLS NOT DISTINCT allows only one per domain.
  await db.query("INSERT INTO external_domains (domain, category) VALUES ('chatgpt.com', 'genai_llm')");
  await rejectsConstraint(db.query("INSERT INTO external_domains (domain, category) VALUES ('chatgpt.com', 'genai_llm')"));
  await db.query("INSERT INTO external_domains (org_id, domain, category, is_sanctioned) VALUES (?, 'chatgpt.com', 'genai_llm', ?)", [orgId, true]);
  await db.close();
});

test('matches the live PostgreSQL database', { skip: !process.env.CRIMGUARD_DATABASE_URL && 'set CRIMGUARD_DATABASE_URL to compare against PostgreSQL' }, async () => {
  const pg = await connectCrimGuard({ mode: 'postgres' });
  const sqlite = await memoryDb();
  try {
    const { rows } = await pg.query(
      `SELECT c.table_name, c.column_name FROM information_schema.columns c
       JOIN information_schema.tables t USING (table_schema, table_name)
       WHERE c.table_schema = 'public' ORDER BY c.table_name, c.ordinal_position`,
    );
    const pgColumns = {};
    for (const { table_name: table, column_name: column } of rows) (pgColumns[table] ||= []).push(column);
    const sqliteColumns = {};
    for (const table of Object.keys(pgColumns)) sqliteColumns[table] = await columnsOf(sqlite, table);
    assert.deepEqual(sqliteColumns, pgColumns);

    const catalog = 'SELECT * FROM feature_catalog ORDER BY feature_key';
    assert.deepEqual((await sqlite.query(catalog)).rows, (await pg.query(catalog)).rows);
  } finally {
    await pg.close();
    await sqlite.close();
  }
});
