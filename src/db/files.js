'use strict';

class DuplicateFileNameError extends Error {}

// Files are only ever reached through a project: every query is scoped by project_id, and the routes
// check that the project belongs to the signed-in person first. Listing never loads file contents.
// Adding, renaming, replacing or deleting a file also marks its project as updated.
function createFileStore(db, { transaction }) {
  const columns = 'id, name, type, size, created_at, updated_at';
  const q = {
    list: db.prepare(`SELECT ${columns} FROM project_files WHERE project_id = ? ORDER BY updated_at DESC, id DESC`),
    get: db.prepare(`SELECT ${columns} FROM project_files WHERE id = ? AND project_id = ?`),
    content: db.prepare('SELECT name, content FROM project_files WHERE id = ? AND project_id = ?'),
    idByName: db.prepare('SELECT id FROM project_files WHERE project_id = ? AND name = ?'),
    insert: db.prepare('INSERT INTO project_files (project_id, name, type, size, content) VALUES (?, ?, ?, ?, ?)'),
    rename: db.prepare("UPDATE project_files SET name = ?, updated_at = datetime('now') WHERE id = ? AND project_id = ?"),
    replace: db.prepare("UPDATE project_files SET type = ?, size = ?, content = ?, updated_at = datetime('now') WHERE id = ? AND project_id = ?"),
    remove: db.prepare('DELETE FROM project_files WHERE id = ? AND project_id = ?'),
    touchProject: db.prepare("UPDATE projects SET updated_at = datetime('now') WHERE id = ?"),
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
  };
}

module.exports = { DuplicateFileNameError, createFileStore };
