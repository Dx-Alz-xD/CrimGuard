-- =========================================================
-- Red web app — 005: Login throttling and the audit log
-- =========================================================

-- Failed-attempt counters for login, sign-up and password checks.
-- Keys look like "login:email:<email>" or "login:ip:<address>".
-- Stored in the database so a restart doesn't reset an attacker's count.
CREATE TABLE auth_throttle (
    key           TEXT PRIMARY KEY,
    attempts      INTEGER NOT NULL DEFAULT 0,
    window_start  INTEGER NOT NULL,          -- ms since epoch
    blocked_until INTEGER NOT NULL DEFAULT 0 -- ms since epoch
);

-- Security-relevant events. Emails are copied in so entries stay readable
-- after an account is deleted. No passwords, tokens or typed-in emails of
-- unknown accounts are ever written here.
CREATE TABLE audit_log (
    id             INTEGER PRIMARY KEY,
    occurred_at    TEXT NOT NULL DEFAULT (datetime('now')),
    action         TEXT NOT NULL,
    actor_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_email    TEXT,
    target_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    target_email   TEXT,
    ip             TEXT,
    user_agent     TEXT CHECK (user_agent IS NULL OR length(user_agent) <= 255),
    details        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details))
);

CREATE INDEX audit_log_by_time ON audit_log(occurred_at DESC, id DESC);
CREATE INDEX audit_log_by_target ON audit_log(target_user_id, occurred_at DESC);
