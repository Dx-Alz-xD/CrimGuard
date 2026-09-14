-- =========================================================
-- Red web app — 012: A code before downloading above clearance
--
--   download_verifications  one row per session per file above that
--                           person's clearance they have tried to download:
--                           wrong codes so far, and a verified code waiting
--                           to be spent on the download.
--
-- Per session, like mfa_verifications: a code proves who is at this device,
-- so it cannot be carried to another. Per file, because the point is that
-- each copy of such a file is asked for, not that the session proved itself
-- once. A verified code is spent by the download it was for.
--
-- The rules and the numbers are in src/security/above-clearance.js.
-- =========================================================

CREATE TABLE download_verifications (
    token_hash  TEXT NOT NULL,
    file_id     INTEGER NOT NULL REFERENCES project_files(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    demanded_at TEXT NOT NULL DEFAULT (datetime('now')),
    attempts    INTEGER NOT NULL DEFAULT 0,
    -- ISO time a correct code was entered; NULL once the download has used it.
    verified_at TEXT,
    PRIMARY KEY (token_hash, file_id)
) WITHOUT ROWID;

CREATE INDEX idx_download_verifications_user ON download_verifications (user_id);
