'use strict';

// The latest risk score for a CrimGuard person. Biometrics, honeytrapping and the identity
// throttle all decide on it, so it is read in one place.

async function latestScore(db, crimUserId) {
  const { rows } = await db.query(
    `SELECT r.final_score, r.risk_level, r.scenario, r.dashboard_payload, s.snapshot_date FROM risk_scores r
     JOIN risk_feature_snapshot s ON s.id = r.snapshot_id
     WHERE r.user_id = ? ORDER BY s.snapshot_date DESC, r.scored_at DESC LIMIT 1`,
    [crimUserId],
  );
  const row = rows[0];
  if (!row) return null;
  let payload = row.dashboard_payload;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch { payload = null; }
  }
  return {
    score: Number(row.final_score),
    level: row.risk_level,
    scenario: row.scenario,
    snapshotDate: String(row.snapshot_date).slice(0, 10),
    payload: payload || {},
  };
}

module.exports = { latestScore };
