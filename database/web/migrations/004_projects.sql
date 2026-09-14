-- =========================================================
-- Red web app — 004: Projects
-- The dashboard lists a person's projects newest first; this index
-- serves that query without a sort.
-- =========================================================

DROP INDEX IF EXISTS projects_by_owner;
CREATE INDEX projects_by_owner_updated ON projects(owner_id, updated_at DESC, id DESC);
