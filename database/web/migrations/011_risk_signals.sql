-- =========================================================
-- Red web app — 011: Adjustments, email reputation, OTP step-up
--
--   risk_adjustments   signed deltas applied on top of the engine's score.
--                      Negative is a mitigation (someone proved who they
--                      are); positive is an aggravation (their address turns
--                      up in a breach corpus, or is a throwaway).
--   email_reputation   what the login-time checks found, cached per account
--                      so signing in never waits on a third party twice.
--   mfa_verifications  the OTP step-up demanded of one session once its
--                      score has stayed high for a while after sign-in.
--
-- Why adjustments rather than editing the score. The engine's output is a
-- measurement: rewriting it would falsify the detection record, and the next
-- scoring run recomputes from snapshots and would wipe the change anyway.
-- A dated, signed delta sits beside it instead, so the effective score is
-- `engine score + Σ live deltas`, an admin can see exactly what was
-- discounted or added and why, and each one can expire on its own.
--
-- The deltas and the thresholds live in src/security/risk-signals.js.
-- =========================================================

CREATE TABLE risk_adjustments (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Negative lowers the effective score, positive raises it.
    delta      REAL NOT NULL CHECK (delta >= -100 AND delta <= 100),
    -- What produced it: 'mfa_verified', 'email_breached', 'email_disposable', ...
    kind       TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- NULL never expires; otherwise it stops counting on its own.
    expires_at TEXT
);

-- One live adjustment per account per kind: a fresh check replaces the last one
-- rather than stacking on it.
CREATE UNIQUE INDEX idx_risk_adjustments_kind ON risk_adjustments (user_id, kind);
CREATE INDEX idx_risk_adjustments_user ON risk_adjustments (user_id, expires_at);

CREATE TABLE email_reputation (
    user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    domain       TEXT NOT NULL,
    -- NULL everywhere means "not checked", never "clean": a provider being
    -- down and an address being fine are different facts, and the risk
    -- pipeline already draws that line (see telemetry/coverage.js).
    breached     INTEGER,
    breach_count INTEGER,
    breaches     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(breaches)),
    disposable   INTEGER,
    valid        INTEGER,
    blocked      INTEGER,
    detail       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    checked_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE mfa_verifications (
    -- The session it belongs to, hashed the same way sessions are: a step-up
    -- proves who is at *this* device, so it cannot be shared with another.
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    demanded_at TEXT NOT NULL DEFAULT (datetime('now')),
    passed_at   TEXT,
    attempts    INTEGER NOT NULL DEFAULT 0,
    -- The effective score when it was demanded, so the discount can be judged later.
    score_at    REAL
);

CREATE INDEX idx_mfa_verifications_user ON mfa_verifications (user_id, passed_at);
