'use strict';

// Every project query is scoped by owner_id: another account's project is indistinguishable from a missing one.
function createProjectStore(db) {
  // file_count lets the project list show how many files each project holds.
  const columns = 'id, name, description, status, created_at, updated_at, (SELECT COUNT(*) FROM project_files f WHERE f.project_id = projects.id) AS file_count';
  const q = {
    list: db.prepare(`SELECT ${columns} FROM projects WHERE owner_id = ? ORDER BY updated_at DESC, id DESC`),
    get: db.prepare(`SELECT ${columns} FROM projects WHERE id = ? AND owner_id = ?`),
    insert: db.prepare('INSERT INTO projects (owner_id, name, description, status) VALUES (?, ?, ?, ?)'),
    update: db.prepare(`
      UPDATE projects SET name = ?, description = ?, status = ?, updated_at = datetime('now')
      WHERE id = ? AND owner_id = ?`),
    remove: db.prepare('DELETE FROM projects WHERE id = ? AND owner_id = ?'),
  };

  return {
    list: (ownerId) => q.list.all(ownerId),
    get: (id, ownerId) => q.get.get(id, ownerId),
    create: (ownerId, { name, description, status }) => {
      const { lastInsertRowid } = q.insert.run(ownerId, name, description, status);
      return q.get.get(lastInsertRowid, ownerId);
    },
    update: (id, ownerId, { name, description, status }) => {
      q.update.run(name, description, status, id, ownerId);
      return q.get.get(id, ownerId);
    },
    remove: (id, ownerId) => q.remove.run(id, ownerId).changes > 0,
  };
}

module.exports = { createProjectStore };
