-- =========================================================
-- Red web app — 009: Sharing a whole project with a role
--
--   project_role_grants  a project shared with everyone in a role. Every
--                        file in it follows, including ones added later,
--                        which is the point: a per-file grant has to be
--                        repeated each time someone uploads something.
--
-- Clearance still applies. Sharing a project with the interns does not hand
-- them a Secret file inside it; it hands them the files their clearance
-- already covers. The rule is written in db/files.js and nowhere else.
-- =========================================================

CREATE TABLE project_role_grants (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role_id    INTEGER NOT NULL REFERENCES roles(id)    ON DELETE CASCADE,
    granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (project_id, role_id)
);

-- Looking up "which projects is this role in" happens on every file list.
CREATE INDEX idx_project_role_grants_role ON project_role_grants (role_id);
