'use strict';

// Fixed-window failure counters kept in SQLite (table auth_throttle).
//
// A key is blocked for `blockMs` once it records `limit` failures inside `windowMs`.
// Counting only failures means a person who signs in correctly is never slowed down,
// and an attacker can't lock someone out faster than the limit allows.

function createThrottle(db, { now = Date.now } = {}) {
  const q = {
    get: db.prepare('SELECT attempts, window_start, blocked_until FROM auth_throttle WHERE key = ?'),
    upsert: db.prepare(`
      INSERT INTO auth_throttle (key, attempts, window_start, blocked_until) VALUES (?, ?, ?, ?)
      ON CONFLICT (key) DO UPDATE SET attempts = excluded.attempts, window_start = excluded.window_start,
                                      blocked_until = excluded.blocked_until`),
    remove: db.prepare('DELETE FROM auth_throttle WHERE key = ?'),
    purge: db.prepare('DELETE FROM auth_throttle WHERE window_start < ? AND blocked_until < ?'),
  };

  // Seconds until the key may try again, or 0 if it isn't blocked.
  function retryAfter(key) {
    const row = q.get.get(key);
    const wait = row ? row.blocked_until - now() : 0;
    return wait > 0 ? Math.ceil(wait / 1000) : 0;
  }

  // Records one failure. Returns the seconds the key is now blocked for (0 if still allowed).
  function fail(key, { limit, windowMs, blockMs }) {
    const t = now();
    const row = q.get.get(key);
    const fresh = !row || t - row.window_start >= windowMs;
    const attempts = fresh ? 1 : row.attempts + 1;
    const windowStart = fresh ? t : row.window_start;
    const blockedUntil = attempts >= limit ? t + blockMs : (row?.blocked_until ?? 0);
    q.upsert.run(key, attempts, windowStart, blockedUntil);
    return blockedUntil > t ? Math.ceil((blockedUntil - t) / 1000) : 0;
  }

  // Failures recorded in the current window, or 0 once it has lapsed. Read-only: used to make the
  // sign-in proof-of-work harder for a key that has been getting it wrong.
  function failures(key, windowMs) {
    const row = q.get.get(key);
    if (!row) return 0;
    return now() - row.window_start >= windowMs ? 0 : row.attempts;
  }

  const reset = (key) => { q.remove.run(key); };

  // Rows whose window and block have both lapsed carry no information.
  const purge = (maxWindowMs) => { const t = now(); q.purge.run(t - maxWindowMs, t); };

  return { retryAfter, failures, fail, reset, purge };
}

module.exports = { createThrottle };
