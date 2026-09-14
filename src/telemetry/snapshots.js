'use strict';

// Writes a day's 100 variables into risk_feature_snapshot and the ten feat_* tables, and
// reads them back out through v_risk_feature_vector for the risk engine.
//
// The layout comes from feature_catalog rather than a hard-coded list, so adding a variable to
// the catalog is enough for it to be stored: `category` names the table (feat_<category>) and
// `feature_key` names the column, exactly as 06_feature_snapshots.sql defines them.

const SAFE_NAME = /^[a-z][a-z0-9_]*$/;

// category -> the columns that live in feat_<category>.
function featureLayout(catalogRows) {
  const layout = new Map();
  for (const row of catalogRows) {
    const category = row.category ?? row.categoryName;
    const key = row.feature_key ?? row.key;
    if (!SAFE_NAME.test(category) || !SAFE_NAME.test(key)) {
      throw new Error(`Unusable feature catalog entry: ${category}.${key}`);
    }
    if (!layout.has(category)) layout.set(category, []);
    layout.get(category).push(key);
  }
  return layout;
}

const startOf = (date) => `${date}T00:00:00.000Z`;
const endOf = (date) => `${date}T23:59:59.999Z`;

// Creates the snapshot row for this person and day, or returns the existing one.
async function snapshotId(db, userId, date) {
  const found = await db.query('SELECT id FROM risk_feature_snapshot WHERE user_id = ? AND snapshot_date = ?', [userId, date]);
  if (found.rows.length) return found.rows[0].id;

  await db.query(
    `INSERT INTO risk_feature_snapshot (user_id, snapshot_date, period_start, period_end) VALUES (?, ?, ?, ?)
     ON CONFLICT (user_id, snapshot_date) DO NOTHING`,
    [userId, date, startOf(date), endOf(date)],
  );
  const created = await db.query('SELECT id FROM risk_feature_snapshot WHERE user_id = ? AND snapshot_date = ?', [userId, date]);
  if (!created.rows.length) throw new Error(`Could not create a snapshot for user ${userId} on ${date}.`);
  return created.rows[0].id;
}

// Replaces the day's values. Rewriting rather than merging means a recomputation always
// reflects the events as they stand now, including any that arrived late.
async function writeSnapshot(db, { userId, date, features, layout }) {
  const id = await snapshotId(db, userId, date);

  for (const [category, keys] of layout) {
    const table = `feat_${category}`;
    const present = keys.filter((key) => features[key] !== undefined && features[key] !== null);
    await db.query(`DELETE FROM ${table} WHERE snapshot_id = ?`, [id]);
    if (!present.length) continue;

    const columns = ['snapshot_id', ...present];
    await db.query(
      `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`,
      [id, ...present.map((key) => features[key])],
    );
  }
  return id;
}

// The flattened feature vectors for one person, oldest first, as the engine wants them.
async function readVectors(db, userId, { from, to }) {
  const { rows } = await db.query(
    `SELECT * FROM v_risk_feature_vector WHERE user_id = ? AND snapshot_date >= ? AND snapshot_date <= ?
     ORDER BY snapshot_date`,
    [userId, from, to],
  );
  return rows;
}

// Same-role values for each feature over a date range, so a new account can be judged against
// the people doing the same job instead of against a baseline it doesn't have yet.
async function readPeerValues(db, { orgId, isPrivileged, excludeUserId, from, to, keys }) {
  const { rows } = await db.query(
    `SELECT v.* FROM v_risk_feature_vector v JOIN users u ON u.id = v.user_id
     WHERE u.org_id = ? AND u.is_privileged = ? AND v.user_id <> ?
       AND v.snapshot_date >= ? AND v.snapshot_date <= ?`,
    [orgId, isPrivileged, excludeUserId, from, to],
  );

  const peers = {};
  for (const key of keys) {
    const values = rows.map((row) => row[key]).filter((value) => typeof value === 'number' && Number.isFinite(value));
    if (values.length >= 3) peers[key] = values;
  }
  return peers;
}

module.exports = { featureLayout, writeSnapshot, readVectors, readPeerValues, snapshotId };
