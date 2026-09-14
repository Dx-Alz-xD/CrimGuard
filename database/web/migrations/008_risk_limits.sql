-- =========================================================
-- Red web app — 008: Risk limiting
--
--   user_risk_state        the latest risk score for each account, copied
--                          here from the CrimGuard database after every
--                          scoring run. File visibility is decided in SQL
--                          against red.db, so the score has to be reachable
--                          from the same query.
--   risk_limit_exemptions  one row per account that an admin or the CEO has
--                          switched limiting off for. A row means "not
--                          limited"; no row means the rule applies.
--
-- The rule itself (which score caps clearance by how much) lives in
-- src/security/limits.js, and is applied in the person() CTE in db/files.js.
-- =========================================================

CREATE TABLE user_risk_state (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    score      REAL    NOT NULL CHECK (score >= 0 AND score <= 100),
    level      TEXT    NOT NULL CHECK (level IN ('low', 'medium', 'high', 'critical')),
    scenario   TEXT,
    scored_on  TEXT    NOT NULL,          -- the snapshot date the score is for
    updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- The dashboard sorts by score, and the limit check reads one row at a time.
CREATE INDEX idx_risk_state_score ON user_risk_state (score DESC);

CREATE TABLE risk_limit_exemptions (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Who turned it off. Kept so the dashboard can say whose decision it was, and so a CEO
    -- can see that an admin made it. NULL once that account is deleted.
    set_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    set_by_name TEXT NOT NULL,
    set_by_role TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
