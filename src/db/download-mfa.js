'use strict';

// Codes asked for before downloading a file above your clearance, and when you were given that file.
// The rules that read this are in security/above-clearance.js; this only stores and reads.

const { DOWNLOAD_MFA } = require('../security/above-clearance');

function createDownloadMfaStore(db) {
  const q = {
    // When this person was given this file: the by-name grant, or an admin's release of it,
    // whichever is later. Both columns are datetime('now') text, so MAX compares them correctly.
    accessSince: db.prepare(`
      SELECT MAX(at) AS at FROM (
        SELECT granted_at AS at FROM file_user_grants WHERE file_id = $file AND user_id = $user
        UNION ALL
        SELECT decided_at FROM file_access_requests WHERE file_id = $file AND user_id = $user AND status = 'approved'
      )`),

    row: db.prepare('SELECT * FROM download_verifications WHERE token_hash = ? AND file_id = ?'),
    demand: db.prepare(`
      INSERT INTO download_verifications (token_hash, file_id, user_id) VALUES (?, ?, ?)
      ON CONFLICT (token_hash, file_id) DO NOTHING`),
    wrong: db.prepare('UPDATE download_verifications SET attempts = attempts + 1 WHERE token_hash = ? AND file_id = ?'),
    // A correct code clears the count: the limit is on guessing, not on how many files someone opens.
    pass: db.prepare('UPDATE download_verifications SET verified_at = ?, attempts = 0 WHERE token_hash = ? AND file_id = ?'),
    // Spending it. One statement, so two downloads racing on one code cannot both get through.
    spend: db.prepare(`
      UPDATE download_verifications SET verified_at = NULL
      WHERE token_hash = ? AND file_id = ? AND verified_at IS NOT NULL AND verified_at > ? AND attempts < ?`),
    purgeOrphans: db.prepare('DELETE FROM download_verifications WHERE token_hash NOT IN (SELECT token_hash FROM sessions)'),
  };

  const iso = (ms) => new Date(ms).toISOString();

  return {
    accessSince: (userId, fileId) => q.accessSince.get({ user: userId, file: fileId })?.at ?? null,

    // Uses a verified code for this download. True when there was one to use.
    spend: (tokenHash, fileId, now = Date.now()) =>
      q.spend.run(tokenHash, fileId, iso(now - DOWNLOAD_MFA.validForMs), DOWNLOAD_MFA.maxAttempts).changes > 0,

    // Records that a code is owed for this file on this session, and where the count stands.
    demand({ tokenHash, fileId, userId }) {
      q.demand.run(tokenHash, fileId, userId);
      const attempts = q.row.get(tokenHash, fileId)?.attempts ?? 0;
      return { attempts, remaining: Math.max(0, DOWNLOAD_MFA.maxAttempts - attempts), lockedOut: attempts >= DOWNLOAD_MFA.maxAttempts };
    },

    // Checking a code. Returns what happened: 'passed', 'wrong' or 'locked_out'.
    attempt({ tokenHash, fileId, userId, correct, now = Date.now() }) {
      q.demand.run(tokenHash, fileId, userId);
      const { attempts } = q.row.get(tokenHash, fileId);
      if (attempts >= DOWNLOAD_MFA.maxAttempts) return { status: 'locked_out', attempts };
      if (!correct) {
        q.wrong.run(tokenHash, fileId);
        const next = attempts + 1;
        return { status: next >= DOWNLOAD_MFA.maxAttempts ? 'locked_out' : 'wrong', attempts: next };
      }
      q.pass.run(iso(now), tokenHash, fileId);
      return { status: 'passed', attempts: 0 };
    },

    // Signing out takes these with it, the same as the session step-up.
    purge: () => q.purgeOrphans.run().changes,
  };
}

module.exports = { createDownloadMfaStore };
