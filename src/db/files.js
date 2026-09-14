'use strict';

const { PRIVILEGED_ROLES } = require('../security/access');

class DuplicateFileNameError extends Error {}

// Who can see a file, as SQL. This is the only place the rule is written: the project panel, "Shared
// with me", downloads, the access dialog and the CrimGuard dashboard all go through it.
// In each fragment `f` is the file, `p` its project, and the alias passed in is a person built by
// person(). Someone can see a file when:
//   - it is in one of their own projects
//   - they are an admin or the CEO, and their clearance covers the file's confidentiality
//   - it was shared with them by name, at any confidentiality
//   - it was shared with their role, and the role's clearance covers the file's confidentiality
const PRIVILEGED = PRIVILEGED_ROLES.map((role) => `'${role}'`).join(', ');
const person = (alias, param) =>
  `${alias} AS (SELECT u.id, u.role, r.id AS role_id, r.clearance FROM users u JOIN roles r ON r.name = u.role WHERE u.id = ${param})`;
const sharedWith = (who) => `(
  EXISTS (SELECT 1 FROM file_user_grants g WHERE g.file_id = f.id AND g.user_id = ${who}.id)
  OR (f.confidentiality <= ${who}.clearance
      AND EXISTS (SELECT 1 FROM file_role_grants g WHERE g.file_id = f.id AND g.role_id = ${who}.role_id)))`;
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
      SELECT ${columns}, ${project}
      FROM project_files f JOIN projects p ON p.id = f.project_id JOIN users o ON o.id = p.owner_id, v
      WHERE f.id = $file AND ${visibleTo('v')}`),
    visibleContent: db.prepare(`
      WITH ${person('v', '$viewer')}
      SELECT f.id, f.name, f.content, p.id AS project_id, p.name AS project_name, p.owner_id
      FROM project_files f JOIN projects p ON p.id = f.project_id, v
      WHERE f.id = $file AND ${visibleTo('v')}`),
    // Files other people shared with `t`, limited to what the viewer `v` may see. When someone looks at
    // their own list the two are the same person.
    sharedWith: db.prepare(`
      WITH ${person('t', '$person')}, ${person('v', '$viewer')}
      SELECT f.id, f.name, f.type, f.size, f.confidentiality, f.updated_at, ${project},
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
  };
}

module.exports = { DuplicateFileNameError, createFileStore };
