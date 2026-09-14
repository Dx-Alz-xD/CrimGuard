'use strict';

// Risk adjustments, email reputation and the OTP step-up: the three tables migration 011 adds.
//
// The rule that decides what each is worth is in security/risk-signals.js; this only stores and
// reads. Everything here lives in red.db rather than the CrimGuard database, because every one of
// them has to be readable from the SQL that decides access (the same reason db/risk.js exists).

const { effectiveScore, mfaRequired, MFA } = require('../security/risk-signals');

const bool = (value) => (value === null || value === undefined ? null : Boolean(value));
const parse = (value, fallback) => { try { return JSON.parse(value); } catch { return fallback; } };

function createSignalStore(db) {
  const q = {
    // --- adjustments ---------------------------------------------------------------------
    live: db.prepare(`
      SELECT id, delta, kind, reason, detail, created_at, expires_at
      FROM risk_adjustments
      WHERE user_id = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
      ORDER BY created_at DESC, id DESC`),
    sum: db.prepare(`
      SELECT COALESCE(SUM(delta), 0) AS total FROM risk_adjustments
      WHERE user_id = ? AND (expires_at IS NULL OR expires_at > datetime('now'))`),
    // A fresh finding of the same kind replaces the last one rather than stacking on it.
    put: db.prepare(`
      INSERT INTO risk_adjustments (user_id, delta, kind, reason, detail, expires_at)
      VALUES ($user, $delta, $kind, $reason, $detail, $expires)
      ON CONFLICT (user_id, kind) DO UPDATE SET
        delta = excluded.delta, reason = excluded.reason, detail = excluded.detail,
        created_at = datetime('now'), expires_at = excluded.expires_at`),
    drop: db.prepare('DELETE FROM risk_adjustments WHERE user_id = ? AND kind = ?'),
    dropAll: db.prepare('DELETE FROM risk_adjustments WHERE user_id = ?'),
    purge: db.prepare("DELETE FROM risk_adjustments WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')"),

    // --- email reputation ----------------------------------------------------------------
    reputation: db.prepare('SELECT * FROM email_reputation WHERE user_id = ?'),
    putReputation: db.prepare(`
      INSERT INTO email_reputation (user_id, domain, breached, breach_count, breaches, disposable, valid, blocked, detail, checked_at)
      VALUES ($user, $domain, $breached, $breachCount, $breaches, $disposable, $valid, $blocked, $detail, datetime('now'))
      ON CONFLICT (user_id) DO UPDATE SET
        domain = excluded.domain, breached = excluded.breached, breach_count = excluded.breach_count,
        breaches = excluded.breaches, disposable = excluded.disposable, valid = excluded.valid,
        blocked = excluded.blocked, detail = excluded.detail, checked_at = excluded.checked_at`),

    // --- the step-up ---------------------------------------------------------------------
    verification: db.prepare('SELECT * FROM mfa_verifications WHERE token_hash = ?'),
    demand: db.prepare(`
      INSERT INTO mfa_verifications (token_hash, user_id, score_at)
      VALUES (?, ?, ?) ON CONFLICT (token_hash) DO NOTHING`),
    pass: db.prepare("UPDATE mfa_verifications SET passed_at = datetime('now') WHERE token_hash = ?"),
    countAttempt: db.prepare('UPDATE mfa_verifications SET attempts = attempts + 1 WHERE token_hash = ?'),
    // Signing out, or being signed out, takes the step-up with it: a new session proves itself again.
    forgetSession: db.prepare('DELETE FROM mfa_verifications WHERE token_hash = ?'),
    forgetUser: db.prepare('DELETE FROM mfa_verifications WHERE user_id = ?'),
    // Signing out, an admin's reset and a honeytoken revocation all just delete the session. This
    // sweeps up whatever they left behind, so a passed step-up cannot outlive the session that
    // earned it, and the table cannot grow without bound.
    purgeOrphans: db.prepare('DELETE FROM mfa_verifications WHERE token_hash NOT IN (SELECT token_hash FROM sessions)'),
    // The most recent pass on any of this account's sessions, for the admin view.
    lastPass: db.prepare(`
      SELECT passed_at, score_at FROM mfa_verifications
      WHERE user_id = ? AND passed_at IS NOT NULL ORDER BY passed_at DESC LIMIT 1`),
  };

  const adjustments = (userId) => q.live.all(userId).map((row) => ({
    id: row.id,
    kind: row.kind,
    delta: Number(row.delta),
    reason: row.reason,
    detail: parse(row.detail, {}),
    createdAt: row.created_at,
    expiresAt: row.expires_at,
  }));

  const total = (userId) => Number(q.sum.get(userId).total);

  function reputation(userId) {
    const row = q.reputation.get(userId);
    if (!row) return null;
    return {
      domain: row.domain,
      breached: bool(row.breached),
      breachCount: row.breach_count === null ? null : Number(row.breach_count),
      breaches: parse(row.breaches, []),
      disposable: bool(row.disposable),
      valid: bool(row.valid),
      blocked: bool(row.blocked),
      detail: parse(row.detail, {}),
      checkedAt: row.checked_at,
    };
  }

  return {
    // --- adjustments ---------------------------------------------------------------------
    adjustments,
    total,
    // The engine's score with every live delta applied. `base` comes from user_risk_state.
    effective: (userId, base) => effectiveScore(base, [total(userId)]),
    put: (userId, { delta, kind, reason = '', detail = {}, expiresAt = null }) => {
      q.put.run({
        user: userId, delta, kind, reason,
        detail: JSON.stringify(detail), expires: expiresAt,
      });
    },
    drop: (userId, kind) => q.drop.run(userId, kind).changes > 0,
    dropAll: (userId) => q.dropAll.run(userId).changes,
    purge: () => q.purge.run().changes + q.purgeOrphans.run().changes,

    // --- email reputation ----------------------------------------------------------------
    reputation,
    putReputation: (userId, value) => {
      q.putReputation.run({
        user: userId,
        domain: value.domain,
        breached: value.breached === null ? null : Number(Boolean(value.breached)),
        breachCount: value.breachCount ?? null,
        breaches: JSON.stringify(value.breaches ?? []),
        disposable: value.disposable === null ? null : Number(Boolean(value.disposable)),
        valid: value.valid === null ? null : Number(Boolean(value.valid)),
        blocked: value.blocked === null ? null : Number(Boolean(value.blocked)),
        detail: JSON.stringify(value.detail ?? {}),
      });
    },

    // --- the step-up ---------------------------------------------------------------------
    verification: (tokenHash) => q.verification.get(tokenHash) ?? null,
    lastPass: (userId) => q.lastPass.get(userId) ?? null,
    forgetSession: (tokenHash) => { q.forgetSession.run(tokenHash); },
    forgetUser: (userId) => { q.forgetUser.run(userId); },

    // Whether this session must prove itself, recording the demand the first time it does.
    demand({ userId, tokenHash, score, sessionAgeMs, now = Date.now() }) {
      const existing = q.verification.get(tokenHash) ?? null;
      const required = mfaRequired({ score, sessionAgeMs, passedAt: existing?.passed_at ?? null, now });
      if (!required) {
        return { required: false, passed: Boolean(existing?.passed_at), attempts: existing?.attempts ?? 0 };
      }
      if (!existing) q.demand.run(tokenHash, userId, score);
      const row = q.verification.get(tokenHash);
      return {
        required: true,
        passed: false,
        attempts: row?.attempts ?? 0,
        lockedOut: (row?.attempts ?? 0) >= MFA.maxAttempts,
        scoreAt: row?.score_at ?? score,
      };
    },

    // Checking a code. Returns what happened; the caller applies the discount.
    attempt({ tokenHash, correct }) {
      const row = q.verification.get(tokenHash);
      if (!row) return { status: 'not_required' };
      if (row.passed_at) return { status: 'already_passed' };
      if (row.attempts >= MFA.maxAttempts) return { status: 'locked_out', attempts: row.attempts };
      q.countAttempt.run(tokenHash);
      if (!correct) {
        const attempts = row.attempts + 1;
        return { status: attempts >= MFA.maxAttempts ? 'locked_out' : 'wrong', attempts };
      }
      q.pass.run(tokenHash);
      return { status: 'passed', scoreAt: row.score_at };
    },
  };
}

module.exports = { createSignalStore };
