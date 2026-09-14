-- migrate: foreign_keys off
-- =========================================================
-- Red web app — 007: Roles with clearance, and access to files
--
--   roles             intern, employee, admin and ceo, plus any the CEO
--                     adds. clearance (1-5) is the most confidential file
--                     a role's members can be given.
--   users.role        now names a row in roles. Existing users become
--                     employees; admins stay admins.
--   project_files.confidentiality   1 (Open) to 5 (Secret)
--   file_role_grants  a file shared with everyone in a role
--   file_user_grants  a file shared with one person
--
-- users is rebuilt because SQLite can't drop the old CHECK on role. That
-- needs foreign keys off (the first line of this file), or dropping the
-- old table would cascade into credentials, profiles, projects and
-- sessions. The runner still checks every foreign key before committing.
-- =========================================================

CREATE TABLE roles (
    id         INTEGER PRIMARY KEY,
    -- The stable key users.role points at. Never changes once created.
    name       TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 2 AND 32 AND name NOT GLOB '*[^a-z0-9_]*'),
    label      TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(label) BETWEEN 1 AND 40),
    clearance  INTEGER NOT NULL CHECK (clearance BETWEEN 1 AND 5),
    built_in   INTEGER NOT NULL DEFAULT 0 CHECK (built_in IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO roles (name, label, clearance, built_in) VALUES
    ('intern',   'Intern',   1, 1),
    ('employee', 'Employee', 2, 1),
    ('admin',    'Admin',    4, 1),
    ('ceo',      'CEO',      5, 1);

CREATE TABLE users_new (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role          TEXT NOT NULL DEFAULT 'intern' REFERENCES roles(name),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT,
    last_login_at TEXT
);

INSERT INTO users_new (id, name, email, role, created_at, updated_at, last_login_at)
SELECT id, name, email, CASE role WHEN 'admin' THEN 'admin' ELSE 'employee' END, created_at, updated_at, last_login_at
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- Counting a role's members, and refusing to delete a role someone still holds.
CREATE INDEX users_by_role ON users(role);

ALTER TABLE project_files ADD COLUMN confidentiality INTEGER NOT NULL DEFAULT 2 CHECK (confidentiality BETWEEN 1 AND 5);

CREATE TABLE file_role_grants (
    file_id    INTEGER NOT NULL REFERENCES project_files(id) ON DELETE CASCADE,
    role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    granted_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (file_id, role_id)
) WITHOUT ROWID;

CREATE INDEX file_role_grants_by_role ON file_role_grants(role_id);

CREATE TABLE file_user_grants (
    file_id    INTEGER NOT NULL REFERENCES project_files(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    granted_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (file_id, user_id)
) WITHOUT ROWID;

CREATE INDEX file_user_grants_by_user ON file_user_grants(user_id);
