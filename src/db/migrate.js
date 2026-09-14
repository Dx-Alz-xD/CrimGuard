'use strict';

const fs = require('node:fs');
const path = require('node:path');

const MIGRATIONS_DIR = path.join(__dirname, '..', '..', 'database', 'web', 'migrations');

// A migration that rebuilds a table other tables point at (see 007) has to run with foreign key
// enforcement off, or dropping the old table would cascade into everything that references it.
// SQLite only changes that setting outside a transaction, so such a file opts in with this line.
// The foreign_key_check before COMMIT still refuses anything left pointing nowhere.
const FOREIGN_KEYS_OFF = /^--\s*migrate:\s*foreign_keys\s+off\s*$/m;

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

    const sql = fs.readFileSync(path.join(dir, file), 'utf8');
    const keysOff = FOREIGN_KEYS_OFF.test(sql) && db.prepare('PRAGMA foreign_keys').get().foreign_keys === 1;
    if (keysOff) db.exec('PRAGMA foreign_keys = OFF');
    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec(sql);
      record.run(version, file);
      const problems = db.prepare('PRAGMA foreign_key_check').all();
      if (problems.length) throw new Error(`foreign key check failed: ${JSON.stringify(problems.slice(0, 3))}`);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      err.message = `Migration ${file} failed: ${err.message}`;
      throw err;
    } finally {
      if (keysOff) db.exec('PRAGMA foreign_keys = ON');
    }
    ran.push(file);
  }
  return ran;
}

module.exports = { MIGRATIONS_DIR, migrate };
