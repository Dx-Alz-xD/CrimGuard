'use strict';

function createSessionStore(db) {
  const q = {
    insert: db.prepare(`
      INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, user_agent)
      VALUES (?, ?, ?, ?, ?, ?)`),
    // Name and role are read from users on every request, so a role change applies to open sessions.
    find: db.prepare(`
      SELECT s.token_hash, s.created_at, s.last_seen_at, s.expires_at,
             u.id, u.name, u.email, u.role, c.must_change_password
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      JOIN user_credentials c ON c.user_id = u.id
      WHERE s.token_hash = ?`),
    touch: db.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?'),
    remove: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    removeOthers: db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?'),
    removeAll: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
    purgeExpired: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
    trim: db.prepare(`
      DELETE FROM sessions WHERE user_id = ? AND token_hash NOT IN (
        SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?)`),
  };

  return {
    insert: ({ tokenHash, userId, now, expiresAt, userAgent }) => {
      q.insert.run(tokenHash, userId, now, now, expiresAt, userAgent);
    },
    find: (tokenHash) => q.find.get(tokenHash),
    touch: (tokenHash, now) => { q.touch.run(now, tokenHash); },
    remove: (tokenHash) => { q.remove.run(tokenHash); },
    removeOthers: (userId, keepTokenHash) => { q.removeOthers.run(userId, keepTokenHash); },
    removeAll: (userId) => { q.removeAll.run(userId); },
    purgeExpired: (now) => { q.purgeExpired.run(now); },
    // Keeps only a person's newest `keep` sessions.
    trim: (userId, keep) => { q.trim.run(userId, userId, keep); },
  };
}

module.exports = { createSessionStore };
