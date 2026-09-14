-- =========================================================
-- Red web app — 002: Accounts, credentials and profiles
--
--   users             who someone is and what role they have (sign-up)
--   user_credentials  how they prove it (login). Kept out of `users` so
--                     no query that lists or loads people can return a
--                     password hash by accident.
--   user_profiles     optional details a person keeps about themselves
-- =========================================================

ALTER TABLE users ADD COLUMN updated_at TEXT;
ALTER TABLE users ADD COLUMN last_login_at TEXT;
UPDATE users SET updated_at = created_at WHERE updated_at IS NULL;

CREATE TABLE user_credentials (
    user_id              INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- PHC string: $argon2id$v=19$m=…,t=…,p=…$salt$hash
    -- (legacy scrypt$… hashes are upgraded the next time the person signs in)
    password_hash        TEXT NOT NULL,
    -- Set when an admin chooses the password, so only the person themself knows the one they use.
    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
    password_changed_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO user_credentials (user_id, password_hash, password_changed_at)
SELECT id, password_hash, created_at FROM users;

ALTER TABLE users DROP COLUMN password_hash;

CREATE TABLE user_profiles (
    user_id      INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    job_title    TEXT NOT NULL DEFAULT '' CHECK (length(job_title) <= 80),
    organization TEXT NOT NULL DEFAULT '' CHECK (length(organization) <= 80),
    bio          TEXT NOT NULL DEFAULT '' CHECK (length(bio) <= 500),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO user_profiles (user_id) SELECT id FROM users;
