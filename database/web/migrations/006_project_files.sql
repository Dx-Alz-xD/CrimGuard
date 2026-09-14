-- =========================================================
-- Red web app — 006: Project files
-- Files people attach to their projects. The contents are stored in
-- the database, so the data volume holds everything, and deleting a
-- project (or its owner) removes its files through the cascade.
-- Names are unique within a project, ignoring case.
-- IF NOT EXISTS lets a database from the release that created this
-- table before migrations existed pass through unchanged.
-- =========================================================

CREATE TABLE IF NOT EXISTS project_files (
    id         INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       TEXT NOT NULL COLLATE NOCASE CHECK (length(name) BETWEEN 1 AND 255),
    type       TEXT NOT NULL DEFAULT 'application/octet-stream' CHECK (length(type) <= 100),
    size       INTEGER NOT NULL CHECK (size >= 0),
    content    BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_id, name)
);

-- The project panel lists a project's files newest first.
CREATE INDEX IF NOT EXISTS project_files_by_project_updated ON project_files(project_id, updated_at DESC, id DESC);
