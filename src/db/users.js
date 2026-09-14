'use strict';

// Accounts (users), their credentials (user_credentials) and profiles (user_profiles).
// Only the login and password-change paths ever read password_hash.

class DuplicateEmailError extends Error {}

function createUserStore(db, { transaction }) {
  const q = {
    loginByEmail: db.prepare(`
      SELECT u.id, u.name, u.email, u.role, r.clearance, c.password_hash, c.must_change_password
      FROM users u JOIN user_credentials c ON c.user_id = u.id JOIN roles r ON r.name = u.role
      WHERE u.email = ?`),
    byId: db.prepare('SELECT u.id, u.name, u.email, u.role, r.clearance FROM users u JOIN roles r ON r.name = u.role WHERE u.id = ?'),
    passwordHash: db.prepare('SELECT password_hash FROM user_credentials WHERE user_id = ?'),

    insertUser: db.prepare("INSERT INTO users (name, email, role, updated_at) VALUES (?, ?, ?, datetime('now'))"),
    insertCredentials: db.prepare('INSERT INTO user_credentials (user_id, password_hash, must_change_password) VALUES (?, ?, ?)'),
    insertProfile: db.prepare('INSERT INTO user_profiles (user_id) VALUES (?)'),

    setRole: db.prepare("UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?"),
    setPassword: db.prepare(`
      UPDATE user_credentials SET password_hash = ?, must_change_password = ?, password_changed_at = datetime('now')
      WHERE user_id = ?`),
    // Only replaces the hash it was computed from, so it can't undo a password change that raced it.
    upgradeHash: db.prepare('UPDATE user_credentials SET password_hash = ? WHERE user_id = ? AND password_hash = ?'),
    recordLogin: db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?"),
    // The account's credentials, profile, projects and sessions go with it (ON DELETE CASCADE).
    remove: db.prepare('DELETE FROM users WHERE id = ?'),

    list: db.prepare(`
      SELECT u.id, u.name, u.email, u.role, r.label AS role_label, r.clearance, u.created_at, u.last_login_at,
             (SELECT COUNT(*) FROM projects p WHERE p.owner_id = u.id) AS project_count
      FROM users u
      JOIN roles r ON r.name = u.role
      ORDER BY u.created_at, u.id`),

    profile: db.prepare(`
      SELECT u.id, u.name, u.email, u.role, u.created_at, u.last_login_at,
             COALESCE(p.job_title, '') AS job_title, COALESCE(p.organization, '') AS organization,
             COALESCE(p.bio, '') AS bio, c.password_changed_at
      FROM users u
      LEFT JOIN user_profiles p ON p.user_id = u.id
      LEFT JOIN user_credentials c ON c.user_id = u.id
      WHERE u.id = ?`),
    setName: db.prepare("UPDATE users SET name = ?, updated_at = datetime('now') WHERE id = ?"),
    upsertProfile: db.prepare(`
      INSERT INTO user_profiles (user_id, job_title, organization, bio) VALUES (?, ?, ?, ?)
      ON CONFLICT (user_id) DO UPDATE SET job_title = excluded.job_title, organization = excluded.organization,
                                          bio = excluded.bio, updated_at = datetime('now')`),
  };

  function create({ name, email, role, passwordHash, mustChangePassword = false }) {
    try {
      return transaction(() => {
        const id = Number(q.insertUser.run(name, email, role).lastInsertRowid);
        q.insertCredentials.run(id, passwordHash, mustChangePassword ? 1 : 0);
        q.insertProfile.run(id);
        return q.byId.get(id);
      });
    } catch (err) {
      if (/UNIQUE constraint failed: users\.email/.test(err.message)) throw new DuplicateEmailError();
      throw err;
    }
  }

  return {
    create,
    findForLogin: (email) => q.loginByEmail.get(email),
    findById: (id) => q.byId.get(id),
    passwordHash: (id) => q.passwordHash.get(id)?.password_hash,
    setRole: (id, role) => q.setRole.run(role, id).changes > 0,
    setPassword: (id, passwordHash, { mustChange = false } = {}) =>
      q.setPassword.run(passwordHash, mustChange ? 1 : 0, id).changes > 0,
    upgradeHash: (id, newHash, oldHash) => { q.upgradeHash.run(newHash, id, oldHash); },
    recordLogin: (id) => { q.recordLogin.run(id); },
    remove: (id) => q.remove.run(id).changes > 0,
    list: () => q.list.all(),
    profile: (id) => q.profile.get(id),
    updateProfile: (id, { name, jobTitle, organization, bio }) => transaction(() => {
      q.setName.run(name, id);
      q.upsertProfile.run(id, jobTitle, organization, bio);
    }),
  };
}

module.exports = { DuplicateEmailError, createUserStore };
