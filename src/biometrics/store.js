'use strict';

// biometric_windows (database/crimguard/09_biometric_windows.sql): one judged window per row.
// Works on PostgreSQL and the SQLite copy through the same db.query interface.

const num = (value) => (value === null || value === undefined ? null : Number(value));

const parse = (row) => ({
  id: Number(row.id),
  userId: Number(row.user_id),
  sessionRef: row.session_ref,
  windowStart: row.window_start,
  windowSeconds: Number(row.window_seconds),
  keystrokes: Number(row.keystrokes),
  pointerStrokes: Number(row.pointer_strokes),
  features: typeof row.features === 'string' ? JSON.parse(row.features) : row.features,
  keysZ: num(row.keys_z),
  pointerZ: num(row.pointer_z),
  distanceZ: num(row.distance_z),
  matchProbability: num(row.match_probability),
  verdict: row.verdict,
  sessionTrust: num(row.session_trust),
  decision: row.decision,
});

function createBiometricStore(db) {
  return {
    async insert({ userId, deviceId, sessionRef, window, result, trust, decision }) {
      await db.query(
        `INSERT INTO biometric_windows
           (user_id, device_id, session_ref, window_start, window_seconds, keystrokes, pointer_strokes, features,
            keys_z, pointer_z, distance_z, match_probability, verdict, session_trust, decision, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, deviceId ?? null, sessionRef ?? null, window.windowStart, window.windowSeconds, window.keys, window.strokes,
          JSON.stringify(window.features), result.zs.keys ?? null, result.zs.pointer ?? null, result.distanceZ, result.matchProbability,
          result.verdict, trust ?? null, decision ?? null, new Date().toISOString()],
      );
    },

    // The windows a profile is built from: the owner's own accepted ones - enrolment windows and
    // windows that matched. Uncertain and mismatched windows never teach the profile anything, or
    // an impostor would slowly become the owner.
    async profileWindows(userId, limit) {
      const { rows } = await db.query(
        `SELECT * FROM biometric_windows WHERE user_id = ? AND verdict IN ('enrolling', 'match')
         ORDER BY window_start DESC, id DESC LIMIT ?`,
        [userId, limit],
      );
      return rows.map(parse).reverse();
    },

    async recent(userId, { limit = 50 } = {}) {
      const { rows } = await db.query('SELECT * FROM biometric_windows WHERE user_id = ? ORDER BY window_start DESC, id DESC LIMIT ?', [userId, limit]);
      return rows.map(parse);
    },

    async onDay(userId, date) {
      const next = new Date(Date.parse(`${date}T00:00:00Z`) + 86400000).toISOString().slice(0, 10);
      const { rows } = await db.query(
        'SELECT * FROM biometric_windows WHERE user_id = ? AND window_start >= ? AND window_start < ? ORDER BY window_start',
        [userId, `${date}T00:00:00.000Z`, `${next}T00:00:00.000Z`],
      );
      return rows.map(parse);
    },
  };
}

module.exports = { createBiometricStore };
