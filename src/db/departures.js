'use strict';

// Leaving dates, and the access requests they cause.
//
// The date is computed in the CrimGuard database, which the website talks to asynchronously, but
// the gate runs on the download path in red.db — so a copy is kept here and refreshed whenever an
// admin changes someone's HR context. Same arrangement, and same reason, as db/risk.js.
//
// The rule that reads all this is in security/departure.js.

const { gateFor, approvalExpiry, describe, daysUntil, NOTICE_WINDOW_DAYS } = require('../security/departure');

function createDepartureStore(db) {
  const columns = `r.id, r.file_id, r.user_id, r.status, r.reason, r.confidentiality,
    r.clearance, r.decided_by, r.decided_by_name, r.note, r.created_at, r.decided_at, r.expires_at`;

  const q = {
    setState: db.prepare(`
      INSERT INTO user_departure_state (user_id, termination_date, updated_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT (user_id) DO UPDATE SET
        termination_date = excluded.termination_date, updated_at = excluded.updated_at`),
    state: db.prepare('SELECT user_id, termination_date, updated_at FROM user_departure_state WHERE user_id = ?'),
    clearState: db.prepare('DELETE FROM user_departure_state WHERE user_id = ?'),
    leaving: db.prepare(`
      SELECT d.user_id, d.termination_date, u.name, u.email, u.role
      FROM user_departure_state d JOIN users u ON u.id = d.user_id
      WHERE d.termination_date IS NOT NULL ORDER BY d.termination_date`),

    // Is this file reachable for this person through an individual grant?
    byName: db.prepare('SELECT 1 FROM file_user_grants WHERE file_id = ? AND user_id = ? LIMIT 1'),

    // The live approval for one file, if there is one. Newest wins: a second approval after an
    // expiry is a fresh key, not an argument with the first.
    approval: db.prepare(`
      SELECT expires_at FROM file_access_requests
      WHERE user_id = ? AND file_id = ? AND status = 'approved'
      ORDER BY decided_at DESC, id DESC LIMIT 1`),

    pending: db.prepare(`SELECT ${columns} FROM file_access_requests r
      WHERE r.file_id = ? AND r.user_id = ? AND r.status = 'pending'`),
    byId: db.prepare(`SELECT ${columns} FROM file_access_requests r WHERE r.id = ?`),
    create: db.prepare(`
      INSERT INTO file_access_requests (file_id, user_id, reason, confidentiality, clearance)
      VALUES (?, ?, ?, ?, ?) RETURNING id`),
    decide: db.prepare(`
      UPDATE file_access_requests
      SET status = ?, decided_by = ?, decided_by_name = ?, note = ?,
          decided_at = datetime('now'), expires_at = ?
      WHERE id = ? AND status = 'pending'`),

    // The queue, with everything the console needs to judge it without a second round trip.
    list: db.prepare(`
      SELECT ${columns},
             f.name AS file_name, f.confidentiality AS file_confidentiality,
             p.id AS project_id, p.name AS project_name,
             u.name AS user_name, u.email AS user_email, u.role AS user_role,
             o.id AS owner_id, o.name AS owner_name, o.email AS owner_email,
             d.termination_date
      FROM file_access_requests r
      JOIN project_files f ON f.id = r.file_id
      JOIN projects p ON p.id = f.project_id
      JOIN users u ON u.id = r.user_id
      JOIN users o ON o.id = p.owner_id
      LEFT JOIN user_departure_state d ON d.user_id = r.user_id
      WHERE (?1 IS NULL OR r.status = ?1)
      ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.created_at DESC, r.id DESC
      LIMIT ?2`),
    mine: db.prepare(`
      SELECT ${columns}, f.name AS file_name, p.name AS project_name
      FROM file_access_requests r
      JOIN project_files f ON f.id = r.file_id
      JOIN projects p ON p.id = f.project_id
      WHERE r.user_id = ? ORDER BY r.created_at DESC, r.id DESC LIMIT ?`),
    countPending: db.prepare("SELECT COUNT(*) AS n FROM file_access_requests WHERE status = 'pending'"),
  };

  const terminationDate = (userId) => q.state.get(userId)?.termination_date ?? null;

  // The one call the download path makes. `file` has already been through the visibility rule, so
  // this only decides whether they may take a copy right now; `clearance` is the effective one,
  // after risk limiting. Returns { gated: false, ... } for almost every request.
  function gate({ userId, fileId, confidentiality, ownerId, clearance, now = Date.now() }) {
    const decision = gateFor({
      terminationDate: terminationDate(userId),
      confidentiality,
      clearance,
      byName: Boolean(q.byName.get(fileId, userId)),
      isOwner: Number(ownerId) === Number(userId),
      approvedUntil: q.approval.get(userId, fileId)?.expires_at ?? null,
      now,
    });
    if (!decision.gated) return decision;
    return {
      ...decision,
      pending: q.pending.get(fileId, userId) ?? null,
      explanation: describe({ daysLeft: decision.daysLeft, confidentiality, clearance }),
    };
  }

  return {
    NOTICE_WINDOW_DAYS,
    state: (userId) => q.state.get(userId) ?? null,
    terminationDate,
    setState: (userId, { terminationDate: date = null }) => { q.setState.run(userId, date); },
    clearState: (userId) => { q.clearState.run(userId); },
    leaving: () => q.leaving.all(),
    gate,

    // Asking. The unique index makes a second ask while one is open a no-op, so a double click or
    // two tabs cannot fill the queue with the same request.
    request: ({ userId, fileId, confidentiality, clearance, reason = '' }) => {
      const existing = q.pending.get(fileId, userId);
      if (existing) return { request: existing, created: false };
      const { id } = q.create.get(fileId, userId, reason, confidentiality, clearance);
      return { request: q.byId.get(id), created: true };
    },

    // Deciding. Returns the row, or null when someone else got there first.
    decide: (id, { approve, by, note = '', now = Date.now() }) => {
      const expires = approve ? approvalExpiry(now) : null;
      const changed = q.decide.run(approve ? 'approved' : 'denied', by.id, by.name, note, expires, id).changes;
      return changed ? q.byId.get(id) : null;
    },

    byId: (id) => q.byId.get(id) ?? null,
    list: ({ status = null, limit = 100 } = {}) => q.list.all(status, limit),
    mine: (userId, { limit = 50 } = {}) => q.mine.all(userId, limit),
    pendingCount: () => q.countPending.get().n,
  };
}

// ---- views ----------------------------------------------------------------------------------

// One request as the person who made it sees it.
const requestView = (row) => ({
  id: row.id,
  fileId: row.file_id,
  status: row.status,
  reason: row.reason,
  confidentiality: row.confidentiality,
  clearance: row.clearance,
  note: row.note,
  decidedBy: row.decided_by_name ?? null,
  createdAt: row.created_at,
  decidedAt: row.decided_at ?? null,
  expiresAt: row.expires_at ?? null,
  ...(row.file_name === undefined ? {} : { file: { name: row.file_name, project: row.project_name ?? null } }),
});

// The same request in the admin queue: who is asking, for what, and how close they are to leaving,
// so it can be decided without opening anything else.
function queueView(row) {
  const daysLeft = daysUntil(row.termination_date ?? null);
  return {
    ...requestView(row),
    file: {
      id: row.file_id,
      name: row.file_name,
      confidentiality: row.file_confidentiality,
      project: { id: row.project_id, name: row.project_name },
    },
    person: {
      id: row.user_id, name: row.user_name, email: row.user_email, role: row.user_role,
      terminationDate: row.termination_date ?? null, daysLeft,
    },
    owner: { id: row.owner_id, name: row.owner_name, email: row.owner_email },
    explanation: describe({ daysLeft, confidentiality: row.confidentiality, clearance: row.clearance }),
  };
}

module.exports = { createDepartureStore, requestView, queueView };
