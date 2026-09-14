'use strict';

const fs = require('node:fs');
const path = require('node:path');

const MIGRATIONS_DIR = path.join(__dirname, '..', '..', 'database', 'web', 'migrations');

// Applies database/web/migrations/NNN_name.sql files that haven't run yet, in order, each in its own
// transaction. A failed migration rolls back completely and stops startup.
function migrate(db, dir = MIGRATIONS_DIR) {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  const applied = new Set(db.prepare('SELECT version FROM schema_migrations').all().map((row) => row.version));
  const record = db.prepare('INSERT INTO schema_migrations (version, name) VALUES (?, ?)');

  const files = fs.readdirSync(dir).filter((file) => /^\d{3}_[\w-]+\.sql$/.test(file)).sort();
  const ran = [];
  for (const file of files) {
    const version = Number(file.slice(0, 3));
    if (applied.has(version)) continue;

    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec(fs.readFileSync(path.join(dir, file), 'utf8'));
      record.run(version, file);
      const problems = db.prepare('PRAGMA foreign_key_check').all();
      if (problems.length) throw new Error(`foreign key check failed: ${JSON.stringify(problems.slice(0, 3))}`);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      err.message = `Migration ${file} failed: ${err.message}`;
      throw err;
    }
    ran.push(file);
  }
  return ran;
}

module.exports = { MIGRATIONS_DIR, migrate };
