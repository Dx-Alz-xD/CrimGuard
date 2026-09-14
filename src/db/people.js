'use strict';

const { PRIVILEGED_ROLES } = require('../security/access');

// Everything Red holds about each person, for the CrimGuard dashboard. Read-only. File names are not
// read here: files go through db/files.js, which applies the viewer's clearance.

const PRIVILEGED = PRIVILEGED_ROLES.map((role) => `'${role}'`).join(', ');

function createPeopleStore(db) {
  // A session counts as live until its absolute expiry or its idle timeout, whichever comes first.
  // Idle timeouts differ by role, so the caller passes the cut-off for each.
  const liveSession = (u) => `s.user_id = ${u}.id AND s.expires_at > $now
    AND s.last_seen_at > CASE WHEN ${u}.role IN (${PRIVILEGED}) THEN $adminSince ELSE $userSince END`;

  const q = {
    overview: db.prepare(`
      SELECT u.id, u.name, u.email, u.role, r.label AS role_label, r.clearance, u.created_at, u.last_login_at,
             COALESCE(pr.job_title, '') AS job_title,
             (SELECT COUNT(*) FROM projects p WHERE p.owner_id = u.id) AS project_count,
             (SELECT COUNT(*) FROM project_files f JOIN projects p ON p.id = f.project_id WHERE p.owner_id = u.id) AS file_count,
             (SELECT COALESCE(SUM(f.size), 0) FROM project_files f JOIN projects p ON p.id = f.project_id WHERE p.owner_id = u.id) AS file_bytes,
             (SELECT COUNT(*) FROM sessions s WHERE ${liveSession('u')}) AS session_count,
             (SELECT MAX(s.last_seen_at) FROM sessions s WHERE ${liveSession('u')}) AS last_seen_at,
             (SELECT COUNT(*) FROM audit_log a
               WHERE (a.actor_id = u.id OR a.target_user_id = u.id) AND a.occurred_at >= datetime('now', '-1 day')) AS events_today
      FROM users u
      JOIN roles r ON r.name = u.role
      LEFT JOIN user_profiles pr ON pr.user_id = u.id
      ORDER BY r.clearance DESC, u.name COLLATE NOCASE, u.id`),
    person: db.prepare(`
      SELECT u.id, u.name, u.email, u.role, r.label AS role_label, r.clearance, u.created_at, u.updated_at, u.last_login_at,
             COALESCE(pr.job_title, '') AS job_title, COALESCE(pr.organization, '') AS organization,
             COALESCE(pr.bio, '') AS bio, c.password_changed_at, c.must_change_password
      FROM users u
      JOIN roles r ON r.name = u.role
      LEFT JOIN user_profiles pr ON pr.user_id = u.id
      LEFT JOIN user_credentials c ON c.user_id = u.id
      WHERE u.id = ?`),
    projects: db.prepare(`
      SELECT p.id, p.name, p.description, p.status, p.created_at, p.updated_at,
             (SELECT COUNT(*) FROM project_files f WHERE f.project_id = p.id) AS file_count
      FROM projects p
      WHERE p.owner_id = ?
      ORDER BY p.updated_at DESC, p.id DESC`),
    sessions: db.prepare(`
      SELECT s.created_at, s.last_seen_at, s.expires_at, s.user_agent
      FROM sessions s, (SELECT id, role FROM users WHERE id = $id) u
      WHERE ${liveSession('u')}
      ORDER BY s.last_seen_at DESC`),
    activity: db.prepare(`
      SELECT id, occurred_at, action, actor_id, actor_email, target_user_id, target_email, ip, details
      FROM audit_log
      WHERE actor_id = $id OR target_user_id = $id
      ORDER BY id DESC
      LIMIT $limit`),
  };

  return {
    overview: ({ now, userSince, adminSince }) => q.overview.all({ now, userSince, adminSince }),
    person: (id) => q.person.get(id),
    projects: (ownerId) => q.projects.all(ownerId),
    sessions: (userId, { now, userSince, adminSince }) => q.sessions.all({ id: userId, now, userSince, adminSince }),
    activity: (userId, limit = 50) =>
      q.activity.all({ id: userId, limit }).map((row) => ({ ...row, details: JSON.parse(row.details) })),
  };
}

module.exports = { createPeopleStore };
