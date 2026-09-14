'use strict';

// Roles: the four built in, and any the CEO adds. The name is the stable key users.role points at and
// never changes; the label can, and so can the clearance of a role the CEO added.

class DuplicateRoleError extends Error {}

// "Field sales" becomes "field_sales". Labels with no Latin letters or digits still get a usable name.
function slug(label) {
  const base = label.normalize('NFKD').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 24);
  return base.length >= 2 ? base : `role_${base}`.replace(/_+$/, '');
}

function createRoleStore(db) {
  const columns = `r.id, r.name, r.label, r.clearance, r.built_in, r.created_at,
    (SELECT COUNT(*) FROM users u WHERE u.role = r.name) AS member_count`;
  const q = {
    list: db.prepare(`SELECT ${columns} FROM roles r ORDER BY r.clearance, r.built_in DESC, r.label`),
    byId: db.prepare(`SELECT ${columns} FROM roles r WHERE r.id = ?`),
    byName: db.prepare(`SELECT ${columns} FROM roles r WHERE r.name = ?`),
    nameTaken: db.prepare('SELECT 1 FROM roles WHERE name = ?'),
    insert: db.prepare('INSERT INTO roles (name, label, clearance) VALUES (?, ?, ?)'),
    update: db.prepare('UPDATE roles SET label = ?, clearance = ? WHERE id = ? AND built_in = 0'),
    // A role someone still holds can't go; the foreign key on users.role would refuse it anyway.
    remove: db.prepare('DELETE FROM roles WHERE id = ? AND built_in = 0 AND NOT EXISTS (SELECT 1 FROM users u WHERE u.role = roles.name)'),
  };

  const out = (row) => row && { ...row, built_in: row.built_in === 1 };

  function uniqueLabel(fn) {
    try {
      return fn();
    } catch (err) {
      if (/UNIQUE constraint failed: roles\.label/.test(err.message)) throw new DuplicateRoleError();
      throw err;
    }
  }

  return {
    list: () => q.list.all().map(out),
    byId: (id) => out(q.byId.get(id)),
    byName: (name) => out(q.byName.get(name)),
    create: ({ label, clearance }) => uniqueLabel(() => {
      const base = slug(label);
      let name = base;
      for (let n = 2; q.nameTaken.get(name); n += 1) name = `${base}_${n}`;
      const { lastInsertRowid } = q.insert.run(name, label, clearance);
      return out(q.byId.get(lastInsertRowid));
    }),
    update: (id, { label, clearance }) =>
      uniqueLabel(() => (q.update.run(label, clearance, id).changes > 0 ? out(q.byId.get(id)) : null)),
    remove: (id) => q.remove.run(id).changes > 0,
  };
}

module.exports = { DuplicateRoleError, createRoleStore };
