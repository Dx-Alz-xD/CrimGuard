-- =========================================================
-- Red web app — 010: Access requests while someone is leaving
--
--   user_departure_state  the leaving date each account carries, copied here
--                         from the CrimGuard database whenever HR context
--                         changes. Access is decided in SQL against red.db,
--                         so the date has to be reachable from the same
--                         query — the same reason user_risk_state exists.
--   file_access_requests  one row per request to open a file that departure
--                         gating is holding back, and an admin's decision.
--
-- What this closes. A file shared with someone *by name* is deliberately not
-- a clearance decision: it opens at any confidentiality, and risk limiting
-- leaves it alone on purpose (see security/limits.js). That is the right
-- default for someone doing their job, and the wrong one for someone working
-- their notice — which is exactly when insider IP theft clusters. So for an
-- account inside its notice window, and only for it, a by-name grant above
-- the account's clearance stops being self-service and needs an admin.
--
-- The window and the rule live in src/security/departure.js and nowhere else.
-- =========================================================

CREATE TABLE user_departure_state (
    user_id          INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- NULL means nobody is leaving: the row is kept so clearing a date is a
    -- write like any other, rather than a delete that has to be got right.
    termination_date TEXT,
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The gate reads one row at a time; the admin console lists everyone leaving.
CREATE INDEX idx_departure_state_date ON user_departure_state (termination_date)
    WHERE termination_date IS NOT NULL;

CREATE TABLE file_access_requests (
    id              INTEGER PRIMARY KEY,
    file_id         INTEGER NOT NULL REFERENCES project_files(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    reason          TEXT NOT NULL DEFAULT '',
    -- The confidentiality and clearance at the time of asking, so a decision
    -- made last week still reads correctly after either has moved.
    confidentiality INTEGER NOT NULL,
    clearance       INTEGER NOT NULL,
    -- Who decided. NULL once that account is deleted, so the name is kept too.
    decided_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    decided_by_name TEXT,
    note            TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    decided_at      TEXT,
    -- An approval is a key to one file, not a promotion: it stops working on
    -- its own, so nobody has to remember to take it back.
    expires_at      TEXT
);

-- One open request per person per file: asking twice is the same ask.
CREATE UNIQUE INDEX idx_file_access_requests_pending ON file_access_requests (file_id, user_id)
    WHERE status = 'pending';
-- The admin console lists what is waiting; the gate looks up a live approval.
CREATE INDEX idx_file_access_requests_queue ON file_access_requests (status, created_at DESC);
CREATE INDEX idx_file_access_requests_grant ON file_access_requests (user_id, file_id, status);
