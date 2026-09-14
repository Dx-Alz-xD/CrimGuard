-- =========================================================
-- Red web app — 003: Sessions with idle and absolute timeouts
-- Rebuilt rather than altered: sessions are short-lived, and starting
-- clean means every session in the table has the new timestamps.
-- Upgrading signs everyone out once.
-- =========================================================

DROP TABLE sessions;

CREATE TABLE sessions (
    -- SHA-256 of the cookie token. The token itself is never stored.
    token_hash    TEXT PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    INTEGER NOT NULL,  -- ms since epoch
    last_seen_at  INTEGER NOT NULL,  -- ms since epoch, drives the idle timeout
    expires_at    INTEGER NOT NULL,  -- ms since epoch, absolute limit
    user_agent    TEXT NOT NULL DEFAULT '' CHECK (length(user_agent) <= 255)
);

CREATE INDEX sessions_by_user ON sessions(user_id, created_at);
CREATE INDEX sessions_by_expiry ON sessions(expires_at);
