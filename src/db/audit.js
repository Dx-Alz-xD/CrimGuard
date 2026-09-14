'use strict';

const RETENTION_DAYS = 365;

function createAuditLog(db) {
  const q = {
    insert: db.prepare(`
      INSERT INTO audit_log (action, actor_id, actor_email, target_user_id, target_email, ip, user_agent, details)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
    list: db.prepare(`
      SELECT id, occurred_at, action, actor_id, actor_email, target_user_id, target_email, ip, details
      FROM audit_log
      WHERE (? IS NULL OR id < ?)
      ORDER BY id DESC
      LIMIT ?`),
    purge: db.prepare(`DELETE FROM audit_log WHERE occurred_at < datetime('now', ?)`),
  };

  // actor and target are { id, email } or null. details must never contain secrets.
  function record(action, { actor = null, target = null, ip = null, userAgent = null, details = {} } = {}) {
    q.insert.run(
      action,
      actor?.id ?? null, actor?.email ?? null,
      target?.id ?? null, target?.email ?? null,
      ip, userAgent ? userAgent.slice(0, 255) : null,
      JSON.stringify(details),
    );
  }

  function list({ limit = 100, before = null } = {}) {
    return q.list.all(before, before, limit).map((row) => ({ ...row, details: JSON.parse(row.details) }));
  }

  const purge = (days = RETENTION_DAYS) => { q.purge.run(`-${days} days`); };

  return { record, list, purge };
}

module.exports = { createAuditLog };
