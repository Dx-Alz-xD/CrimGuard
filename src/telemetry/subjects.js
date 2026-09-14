'use strict';

// Maps the things Red knows about - accounts, projects, pages, browsers - onto the rows the
// CrimGuard schema expects: organizations, users, resources, devices and user_sessions.
//
// Red accounts are matched to CrimGuard people by okta_user_id = 'red:<id>', because Red is
// what authenticates them here. Ids are cached: a telemetry batch must not cost a lookup per
// event. The caches only ever hold ids, so nothing goes stale that matters.

const crypto = require('node:crypto');

const ORG_NAME = 'Red';
const ORG_URI = 'red:org';

// What each kind of Red object is worth if someone walks off with it. criticality_weight is
// the engine's impact term (1-5), so these are the numbers that decide how much a given
// anomaly is allowed to matter.
const RESOURCE_KINDS = {
  project: { type: 'file', sensitivity: 'internal', weight: 2, label: (name) => `Project: ${name}` },
  page: { type: 'saas_app', sensitivity: 'internal', weight: 1, label: (name) => `Page: ${name}` },
  account: { type: 'database', sensitivity: 'confidential', weight: 4, label: (name) => `Account record: ${name}` },
  directory: { type: 'database', sensitivity: 'confidential', weight: 4, label: () => 'People directory' },
  audit: { type: 'database', sensitivity: 'restricted', weight: 5, label: () => 'Security activity log' },
  risk: { type: 'database', sensitivity: 'restricted', weight: 5, label: () => 'Risk console' },
};

const SENSITIVE_KINDS = new Set(['account', 'directory', 'audit', 'risk']);

const isSensitiveUri = (uri) => SENSITIVE_KINDS.has(String(uri).split(':')[1]?.split('/')[0]);

// A stable id for a Red object, e.g. 'red:project/12' or 'red:page/dashboard'.
const resourceUri = (kind, id) => `red:${kind}${id === undefined || id === null ? '' : `/${id}`}`;

const shortHash = (value) => crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 32);

function createSubjects(db) {
  let orgId = null;
  const userIds = new Map(); // red user id -> crimguard user id
  const resourceIds = new Map(); // uri -> crimguard resource id
  const deviceIds = new Map(); // `${fingerprint}` -> crimguard device id

  // INSERT ... ON CONFLICT DO NOTHING then SELECT, rather than RETURNING: it is the one
  // shape that means the same thing in both SQLite and PostgreSQL when the row already exists.
  async function upsertId({ table, insert, params, where, whereParams }) {
    const found = await db.query(`SELECT id FROM ${table} WHERE ${where}`, whereParams);
    if (found.rows.length) return found.rows[0].id;
    await db.query(insert, params);
    const created = await db.query(`SELECT id FROM ${table} WHERE ${where}`, whereParams);
    if (!created.rows.length) throw new Error(`Could not create the ${table} row for telemetry.`);
    return created.rows[0].id;
  }

  async function organization() {
    if (orgId !== null) return orgId;
    orgId = await upsertId({
      table: 'organizations',
      insert: 'INSERT INTO organizations (name, industry, timezone) VALUES (?, ?, ?)',
      params: [ORG_NAME, 'saas', 'UTC'],
      where: 'name = ?',
      whereParams: [ORG_NAME],
    });
    return orgId;
  }

  // The organisation's working hours, which decide what counts as after-hours.
  async function workingHours() {
    const org = await organization();
    const { rows } = await db.query('SELECT work_day_start, work_day_end, timezone FROM organizations WHERE id = ?', [org]);
    const row = rows[0] || {};
    const hour = (value, fallback) => {
      const [h, m] = String(value || '').split(':');
      return Number.isFinite(Number(h)) ? Number(h) + Number(m || 0) / 60 : fallback;
    };
    return { start: hour(row.work_day_start, 9), end: hour(row.work_day_end, 18), timezone: row.timezone || 'UTC' };
  }

  // The CrimGuard person for a Red account, created on first sight and kept in step after that.
  async function forUser(user) {
    const cached = userIds.get(user.id);
    if (cached !== undefined) {
      await db.query('UPDATE users SET is_privileged = ?, updated_at = ? WHERE id = ?', [user.role === 'admin', new Date().toISOString(), cached]);
      return cached;
    }

    const org = await organization();
    const externalId = `red:${user.id}`;
    const id = await upsertId({
      table: 'users',
      insert: `INSERT INTO users (org_id, email, full_name, employment_type, is_privileged, is_analyst, okta_user_id, hire_date)
               VALUES (?, ?, ?, 'full_time', ?, ?, ?, ?)`,
      params: [org, user.email, user.name || user.email, user.role === 'admin', user.role === 'admin', externalId,
        (user.created_at || new Date().toISOString()).slice(0, 10)],
      where: 'org_id = ? AND okta_user_id = ?',
      whereParams: [org, externalId],
    });

    // Email and name can change in Red after the row was created.
    await db.query('UPDATE users SET email = ?, full_name = ?, is_privileged = ?, is_analyst = ?, updated_at = ? WHERE id = ?',
      [user.email, user.name || user.email, user.role === 'admin', user.role === 'admin', new Date().toISOString(), id]);
    userIds.set(user.id, id);
    return id;
  }

  // Red user id -> CrimGuard user id, without creating anything.
  async function lookupUser(redUserId) {
    const cached = userIds.get(redUserId);
    if (cached !== undefined) return cached;
    const org = await organization();
    const { rows } = await db.query('SELECT id FROM users WHERE org_id = ? AND okta_user_id = ?', [org, `red:${redUserId}`]);
    if (!rows.length) return null;
    userIds.set(redUserId, rows[0].id);
    return rows[0].id;
  }

  function forgetUser(redUserId) {
    userIds.delete(redUserId);
  }

  async function forResource(kind, id, name) {
    const spec = RESOURCE_KINDS[kind];
    if (!spec) return null;
    const uri = resourceUri(kind, id);
    const cached = resourceIds.get(uri);
    if (cached !== undefined) return cached;

    const org = await organization();
    const resourceId = await upsertId({
      table: 'resources',
      insert: `INSERT INTO resources (org_id, resource_type, uri, display_name, sensitivity, criticality_weight)
               VALUES (?, ?, ?, ?, ?, ?)`,
      params: [org, spec.type, uri, spec.label(name ?? id ?? ''), spec.sensitivity, spec.weight],
      where: 'org_id = ? AND uri = ?',
      whereParams: [org, uri],
    });
    resourceIds.set(uri, resourceId);
    return resourceId;
  }

  // A browser fingerprint the collector sent. `personal` and `managed` stay false: a page
  // cannot tell an enrolled device from a personal one (see coverage.js).
  async function forDevice(crimUserId, fingerprint, { hostname = null, os = null } = {}) {
    if (!fingerprint) return null;
    const hash = shortHash(fingerprint);
    const cached = deviceIds.get(hash);
    if (cached !== undefined) {
      await db.query('UPDATE devices SET last_seen_at = ? WHERE id = ?', [new Date().toISOString(), cached]);
      return cached;
    }

    const org = await organization();
    const id = await upsertId({
      table: 'devices',
      insert: `INSERT INTO devices (org_id, primary_user_id, fingerprint_hash, hostname, os, agent_version)
               VALUES (?, ?, ?, ?, ?, 'red-web')`,
      params: [org, crimUserId, hash, hostname, os],
      where: 'org_id = ? AND fingerprint_hash = ?',
      whereParams: [org, hash],
    });
    deviceIds.set(hash, id);
    return id;
  }

  // True the first time this account is seen on this fingerprint.
  async function isNewDevice(crimUserId, fingerprint) {
    if (!fingerprint) return false;
    const org = await organization();
    const { rows } = await db.query(
      'SELECT 1 AS seen FROM devices WHERE org_id = ? AND fingerprint_hash = ? AND primary_user_id = ?',
      [org, shortHash(fingerprint), crimUserId],
    );
    return rows.length === 0;
  }

  return {
    organization, workingHours, forUser, lookupUser, forgetUser, forResource, forDevice, isNewDevice,
  };
}

module.exports = { createSubjects, RESOURCE_KINDS, ORG_URI, resourceUri, isSensitiveUri, shortHash };
