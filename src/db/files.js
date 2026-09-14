'use strict';

const { PRIVILEGED_ROLES } = require('../security/access');
const { TIERS, NO_ACCESS } = require('../security/limits');
const { LIVE_DELTA_SQL } = require('../security/risk-signals');

class DuplicateFileNameError extends Error {}

// Who can see a file, as SQL. This is the only place the rule is written: the project panel, "Shared
// with me", downloads, the access dialog and the CrimGuard dashboard all go through it.
// In each fragment `f` is the file, `p` its project, and the alias passed in is a person built by
// person(). Someone can see a file when:
//   - it is in one of their own projects
//   - they are an admin or the CEO, and their clearance covers the file's confidentiality
//   - it was shared with them by name, at any confidentiality
//   - it, or the project holding it, was shared with their role, and the role's clearance covers
//     the file's confidentiality
const PRIVILEGED = PRIVILEGED_ROLES.map((role) => `'${role}'`).join(', ');

// Risk limiting, applied where clearance is read rather than where files are matched, so every
// query below inherits it without knowing it exists. The thresholds and drops come from
// security/limits.js; this is the SQL that puts them to work.
//
// `clearance` is the effective one: the role's, cut to the baseline minus the tier's drop when
// the account is over a threshold and nobody has switched limiting off for it. The role's own
// clearance stays available as role_clearance, because handing out roles and managing files
// are judged on what someone *is*, not on how risky they currently look.
const BASELINE = '(SELECT CAST(AVG(confidentiality) AS INTEGER) FROM project_files)';
// The score limiting runs on is the engine's plus every live adjustment (security/risk-signals.js):
// proving who you are lowers it, a breached or throwaway address raises it. Clamped here the same
// way effectiveScore() clamps it in JavaScript, so both sides of the app agree on one number.
const EFFECTIVE_SCORE = `MIN(100.0, MAX(0.0, s.score + ${LIVE_DELTA_SQL}))`;
const limitCase = (then, otherwise) => `CASE
      WHEN e.user_id IS NOT NULL OR s.score IS NULL THEN ${otherwise}
      ${TIERS.map((tier) => `WHEN ${EFFECTIVE_SCORE} >= ${tier.minScore} THEN ${then(tier)}`).join(' ')}
      ELSE ${otherwise} END`;

const person = (alias, param) => `${alias} AS (
  SELECT u.id, u.role, r.id AS role_id, r.clearance AS role_clearance,
    ${limitCase(
    (tier) => `MAX(${NO_ACCESS}, MIN(r.clearance, COALESCE(${BASELINE}, r.clearance) - ${tier.drop}))`,
    'r.clearance',
  )} AS clearance,
    ${limitCase((tier) => `'${tier.name}'`, 'NULL')} AS limit_tier
  FROM users u
  JOIN roles r ON r.name = u.role
  LEFT JOIN user_risk_state s ON s.user_id = u.id
  LEFT JOIN risk_limit_exemptions e ON e.user_id = u.id
  WHERE u.id = ${param})`;
const sharedWith = (who) => `(
  EXISTS (SELECT 1 FROM file_user_grants g WHERE g.file_id = f.id AND g.user_id = ${who}.id)
  OR (f.confidentiality <= ${who}.clearance
      AND (EXISTS (SELECT 1 FROM file_role_grants g WHERE g.file_id = f.id AND g.role_id = ${who}.role_id)
           OR EXISTS (SELECT 1 FROM project_role_grants g WHERE g.project_id = f.project_id AND g.role_id = ${who}.role_id))))`;
const visibleTo = (who) =>
  `(p.owner_id = ${who}.id OR (${who}.role IN (${PRIVILEGED}) AND f.confidentiality <= ${who}.clearance) OR ${sharedWith(who)})`;

// Files are reached either through a project the signed-in person owns (every query scoped by
// project_id, after the route has checked the project is theirs) or through the visibility rule above.
// Listing never loads file contents. Adding, renaming, replacing or deleting a file also marks its
// project as updated; changing who can see it does not.
function createFileStore(db, { transaction }) {
  const columns = `f.id, f.name, f.type, f.size, f.confidentiality, f.created_at, f.updated_at,
    (SELECT COUNT(*) FROM file_role_grants g WHERE g.file_id = f.id) AS shared_roles,
    (SELECT COUNT(*) FROM file_user_grants g WHERE g.file_id = f.id) AS shared_people`;
  const project = 'p.id AS project_id, p.name AS project_name, o.id AS owner_id, o.name AS owner_name, o.email AS owner_email';

  const q = {
    list: db.prepare(`SELECT ${columns} FROM project_files f WHERE f.project_id = ? ORDER BY f.updated_at DESC, f.id DESC`),
    get: db.prepare(`SELECT ${columns} FROM project_files f WHERE f.id = ? AND f.project_id = ?`),
    content: db.prepare('SELECT name, content FROM project_files WHERE id = ? AND project_id = ?'),
    idByName: db.prepare('SELECT id FROM project_files WHERE project_id = ? AND name = ?'),
    insert: db.prepare('INSERT INTO project_files (project_id, name, type, size, content) VALUES (?, ?, ?, ?, ?)'),
    rename: db.prepare("UPDATE project_files SET name = ?, updated_at = datetime('now') WHERE id = ? AND project_id = ?"),
    replace: db.prepare("UPDATE project_files SET type = ?, size = ?, content = ?, updated_at = datetime('now') WHERE id = ? AND project_id = ?"),
    remove: db.prepare('DELETE FROM project_files WHERE id = ? AND project_id = ?'),
    touchProject: db.prepare("UPDATE projects SET updated_at = datetime('now') WHERE id = ?"),

    visible: db.prepare(`
      WITH ${person('v', '$viewer')}
      SELECT ${columns}, ${project}, v.clearance
      FROM project_files f JOIN projects p ON p.id = f.project_id JOIN users o ON o.id = p.owner_id, v
      WHERE f.id = $file AND ${visibleTo('v')}`),
    visibleContent: db.prepare(`
      WITH ${person('v', '$viewer')}
      SELECT f.id, f.name, f.content, f.confidentiality, p.id AS project_id, p.name AS project_name,
             p.owner_id, v.clearance, v.role_clearance
      FROM project_files f JOIN projects p ON p.id = f.project_id, v
      WHERE f.id = $file AND ${visibleTo('v')}`),
    // Files other people shared with `t`, limited to what the viewer `v` may see. When someone looks at
    // their own list the two are the same person.
    sharedWith: db.prepare(`
      WITH ${person('t', '$person')}, ${person('v', '$viewer')}
      SELECT f.id, f.name, f.type, f.size, f.confidentiality, f.updated_at, ${project}, t.clearance,
             EXISTS (SELECT 1 FROM file_user_grants g WHERE g.file_id = f.id AND g.user_id = t.id) AS by_name
      FROM project_files f JOIN projects p ON p.id = f.project_id JOIN users o ON o.id = p.owner_id, t, v
      WHERE p.owner_id <> t.id AND ${sharedWith('t')} AND ${visibleTo('v')}
      ORDER BY f.updated_at DESC, f.id DESC`),
    // Every file one person owns, each marked with whether the viewer may see it.
    forOwner: db.prepare(`
      WITH ${person('v', '$viewer')}
      SELECT ${columns}, f.project_id, ${visibleTo('v')} AS visible
      FROM project_files f JOIN projects p ON p.id = f.project_id, v
      WHERE p.owner_id = $owner
      ORDER BY f.updated_at DESC, f.id DESC`),

    projectRoleGrants: db.prepare(`
      SELECT r.id, r.name, r.label, r.clearance FROM project_role_grants g JOIN roles r ON r.id = g.role_id
      WHERE g.project_id = ? ORDER BY r.clearance, r.label`),
    revokeProjectRoles: db.prepare('DELETE FROM project_role_grants WHERE project_id = ? AND role_id NOT IN (SELECT value FROM json_each(?))'),
    grantProjectRoles: db.prepare('INSERT OR IGNORE INTO project_role_grants (project_id, role_id, granted_by) SELECT ?, value, ? FROM json_each(?)'),
    // Everyone who already holds a role, with the files granted to each by name. Used to work
    // out what a new account of that role should start with.
    peersInRole: db.prepare(`
      SELECT u.id AS user_id, g.file_id
      FROM users u LEFT JOIN file_user_grants g ON g.user_id = u.id
      WHERE u.role = ? AND u.id <> ?
      ORDER BY u.id`),
    // Those files, with the confidentiality the newcomer's clearance has to cover.
    grantCandidates: db.prepare(`
      SELECT f.id, f.confidentiality FROM project_files f
      WHERE f.id IN (SELECT value FROM json_each(?))`),
    roleGrants: db.prepare(`
      SELECT r.id, r.name, r.label, r.clearance FROM file_role_grants g JOIN roles r ON r.id = g.role_id
      WHERE g.file_id = ? ORDER BY r.clearance, r.label`),
    userGrants: db.prepare(`
      SELECT u.id, u.name, u.email, u.role FROM file_user_grants g JOIN users u ON u.id = g.user_id
      WHERE g.file_id = ? ORDER BY u.name COLLATE NOCASE, u.id`),
    setConfidentiality: db.prepare('UPDATE project_files SET confidentiality = ? WHERE id = ?'),
    // Grants kept across a save keep who made them and when; only the difference is written.
    revokeRoles: db.prepare('DELETE FROM file_role_grants WHERE file_id = ? AND role_id NOT IN (SELECT value FROM json_each(?))'),
    grantRoles: db.prepare('INSERT OR IGNORE INTO file_role_grants (file_id, role_id, granted_by) SELECT ?, value, ? FROM json_each(?)'),
    revokeUsers: db.prepare('DELETE FROM file_user_grants WHERE file_id = ? AND user_id NOT IN (SELECT value FROM json_each(?))'),
    grantUsers: db.prepare('INSERT OR IGNORE INTO file_user_grants (file_id, user_id, granted_by) SELECT ?, value, ? FROM json_each(?)'),
  };

  // Names are checked before an upload is read, but two uploads can still race; the UNIQUE constraint decides.
  function uniqueName(fn) {
    try {
      return fn();
    } catch (err) {
      if (/UNIQUE constraint failed: project_files\./.test(err.message)) throw new DuplicateFileNameError();
      throw err;
    }
  }

  const access = (fileId) => ({ roles: q.roleGrants.all(fileId), people: q.userGrants.all(fileId) });

  return {
    list: (projectId) => q.list.all(projectId),
    get: (id, projectId) => q.get.get(id, projectId),
    content: (id, projectId) => q.content.get(id, projectId),
    // Names compare case-insensitively (the column is COLLATE NOCASE). A file never clashes with itself.
    nameTaken: (projectId, name, exceptId = null) => {
      const row = q.idByName.get(projectId, name);
      return Boolean(row && row.id !== exceptId);
    },
    create: (projectId, { name, type, content }) => uniqueName(() => transaction(() => {
      const id = Number(q.insert.run(projectId, name, type, content.length, content).lastInsertRowid);
      q.touchProject.run(projectId);
      return q.get.get(id, projectId);
    })),
    rename: (id, projectId, name) => uniqueName(() => transaction(() => {
      if (q.rename.run(name, id, projectId).changes === 0) return null;
      q.touchProject.run(projectId);
      return q.get.get(id, projectId);
    })),
    replace: (id, projectId, { type, content }) => transaction(() => {
      if (q.replace.run(type, content.length, content, id, projectId).changes === 0) return null;
      q.touchProject.run(projectId);
      return q.get.get(id, projectId);
    }),
    remove: (id, projectId) => transaction(() => {
      if (q.remove.run(id, projectId).changes === 0) return false;
      q.touchProject.run(projectId);
      return true;
    }),

    // The file with its project and owner if `viewerId` may see it, otherwise undefined.
    visible: (fileId, viewerId) => q.visible.get({ file: fileId, viewer: viewerId }),
    visibleContent: (fileId, viewerId) => q.visibleContent.get({ file: fileId, viewer: viewerId }),
    sharedWith: (personId, viewerId = personId) =>
      q.sharedWith.all({ person: personId, viewer: viewerId }).map((row) => ({ ...row, by_name: row.by_name === 1 })),
    forOwner: (ownerId, viewerId) =>
      q.forOwner.all({ owner: ownerId, viewer: viewerId }).map((row) => ({ ...row, visible: row.visible === 1 })),

    access,
    // Replaces the file's confidentiality and its whole list of roles and people in one transaction.
    setAccess: (fileId, { confidentiality, roleIds, userIds, grantedBy }) => transaction(() => {
      const roles = JSON.stringify(roleIds);
      const people = JSON.stringify(userIds);
      q.setConfidentiality.run(confidentiality, fileId);
      q.revokeRoles.run(fileId, roles);
      q.grantRoles.run(fileId, grantedBy, roles);
      q.revokeUsers.run(fileId, people);
      q.grantUsers.run(fileId, grantedBy, people);
      return access(fileId);
    }),

    // Which roles a whole project is shared with, and setting that list. Every file in the
    // project follows, including ones uploaded afterwards - still bounded by each role's
    // clearance, so this widens who can reach a project, never how sensitive a file may be.
    // One entry per existing holder of `role`, listing the files each was given by name.
    peersInRole: (role, exceptUserId) => {
      const byUser = new Map();
      for (const row of q.peersInRole.all(role, exceptUserId)) {
        if (!byUser.has(row.user_id)) byUser.set(row.user_id, []);
        if (row.file_id != null) byUser.get(row.user_id).push(row.file_id);
      }
      return [...byUser].map(([userId, fileIds]) => ({ userId, fileIds }));
    },
    confidentialityOf: (fileIds) => q.grantCandidates.all(JSON.stringify(fileIds)),
    // Hands a new account the files its role-mates already have. Never widens a file's reach:
    // it only repeats grants that already exist for other people.
    grantToUser: (userId, fileIds, grantedBy) => transaction(() => {
      for (const fileId of fileIds) q.grantUsers.run(fileId, grantedBy, JSON.stringify([userId]));
      return fileIds.length;
    }),

    projectRoles: (projectId) => q.projectRoleGrants.all(projectId),
    setProjectRoles: (projectId, { roleIds, grantedBy }) => transaction(() => {
      const roles = JSON.stringify(roleIds);
      q.revokeProjectRoles.run(projectId, roles);
      q.grantProjectRoles.run(projectId, grantedBy, roles);
      return q.projectRoleGrants.all(projectId);
    }),
  };
}

module.exports = { DuplicateFileNameError, createFileStore };
