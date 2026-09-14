'use strict';

// Connects to the CrimGuard risk database (the 100 risk variables, context ledger,
// scores and alerts). Uses PostgreSQL when CRIMGUARD_DATABASE_URL points at a server
// with the schema loaded, and otherwise falls back to SQLite.
//
// The SQLite file a running server writes to is data/crimguard.db, which git ignores. The first
// time it's needed it is copied from database/crimguard.db, the seed committed to the repo, so
// anyone who clones the repo starts with the shared data - and a server writing its own activity
// never changes a tracked file, which is what made pushes conflict.
//
//   CRIMGUARD_DB            auto (default) | postgres (never fall back) | sqlite
//   CRIMGUARD_DATABASE_URL  postgres://user:password@localhost:5432/crimguard
//   CRIMGUARD_SQLITE_PATH   SQLite file to use (default data/crimguard.db)
//
// Both databases get the same interface: await db.query(sql, params) -> { rows, rowCount },
// with `?` placeholders. Rows come back in the same shape from either one: numbers for
// BIGINT/NUMERIC, true/false for BOOLEAN, parsed JSONB and arrays, ISO 8601 strings for
// TIMESTAMPTZ, and 'YYYY-MM-DD' strings for DATE. Use RETURNING to get inserted ids; both
// databases support it. The SQL itself must be valid in both (check db.dialect if not).

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { buildSqliteSchema, upgradeSqliteSchema, mapOutsideQuotes } = require('./sqlite-schema');

const ROOT = path.join(__dirname, '..', '..');
const DEFAULT_SQLITE_PATH = path.join(ROOT, 'data', 'crimguard.db');
const SEED_SQLITE_PATH = path.join(ROOT, 'database', 'crimguard.db');
const MODES = ['auto', 'postgres', 'sqlite'];

// SQLite can only report declared types for columns read straight from a table. These view
// columns are computed, so their types are listed here to match the PostgreSQL views.
const COMPUTED_VIEW_COLUMNS = { current_roles: 'json', active_ticket_keys: 'json', on_leave_today: 'boolean' };

// node's net module reports a refused localhost connection as an AggregateError with an empty message.
const errorText = (err) => err.message || (err.errors || []).map((e) => e.message).join('; ') || String(err.code || err);

// --- PostgreSQL ----------------------------------------------------------------

function describeUrl(url) {
  try {
    const { hostname, port, pathname } = new URL(url);
    return `${hostname}:${port || 5432}${pathname}`; // never include the password
  } catch {
    return 'an invalid CRIMGUARD_DATABASE_URL';
  }
}

// `?` -> `$1, $2, ...` outside quoted strings.
function toPostgresPlaceholders(sql) {
  let n = 0;
  return mapOutsideQuotes(sql, (code) => code.replace(/\?/g, () => `$${++n}`));
}

async function openPostgres(url) {
  if (!url) throw new Error('CRIMGUARD_DATABASE_URL is not set');
  let pg;
  try {
    pg = require('pg');
  } catch {
    throw new Error("the PostgreSQL driver isn't installed (run npm install)");
  }

  const parseTimestamptz = pg.types.getTypeParser(1184);
  const parsers = {
    20: Number, // BIGINT
    1700: Number, // NUMERIC
    1082: (value) => value, // DATE stays 'YYYY-MM-DD' rather than a local-midnight Date
    1184: (value) => parseTimestamptz(value).toISOString(), // TIMESTAMPTZ
  };
  const pool = new pg.Pool({
    connectionString: url,
    connectionTimeoutMillis: 3000,
    types: { getTypeParser: (oid, format) => parsers[oid] || pg.types.getTypeParser(oid, format) },
  });
  // An idle connection dropping (e.g. the server restarting) must not crash the process.
  pool.on('error', (err) => console.error(`CrimGuard PostgreSQL connection error: ${errorText(err)}`));

  try {
    const { rows } = await pool.query("SELECT to_regclass('public.feature_catalog') IS NOT NULL AS ready");
    if (!rows[0].ready) throw new Error('the CrimGuard schema is not loaded (run database/crimguard/*.sql)');
  } catch (err) {
    await pool.end().catch(() => {});
    throw new Error(`couldn't use PostgreSQL at ${describeUrl(url)}: ${errorText(err)}`);
  }

  return {
    dialect: 'postgres',
    location: describeUrl(url),
    fallbackReason: null,
    async query(sql, params = []) {
      const result = await pool.query(toPostgresPlaceholders(sql), params);
      return { rows: result.rows, rowCount: result.rowCount ?? result.rows.length };
    },
    close: () => pool.end(),
  };
}

// --- SQLite --------------------------------------------------------------------

// Builds the SQLite database at `file` from database/crimguard/*.sql, replacing any existing
// one. It's written to a temporary file and moved into place only once complete, so a failure
// never leaves a half-built database behind. `fill(tempFile)` can add rows before the move.
async function createSqliteDatabase(file, fill) {
  const temp = `${file}.tmp`;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.rmSync(temp, { force: true });
  try {
    const db = new DatabaseSync(temp);
    try {
      db.exec('PRAGMA foreign_keys = ON;');
      db.exec(buildSqliteSchema().sql);
    } finally {
      db.close();
    }
    if (fill) await fill(temp);
    fs.renameSync(temp, file);
  } catch (err) {
    fs.rmSync(temp, { force: true });
    throw err;
  }
}

// Column name -> 'boolean' | 'json', from the declared types in the SQLite schema.
function columnKinds(db) {
  const kinds = new Map(Object.entries(COMPUTED_VIEW_COLUMNS));
  const objects = db.prepare("SELECT name FROM sqlite_schema WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'").all();
  for (const { name } of objects) {
    for (const column of db.prepare('SELECT name, type FROM pragma_table_xinfo(?)').all(name)) {
      const kind = { BOOLEAN: 'boolean', JSONB: 'json' }[column.type.toUpperCase()];
      if (kind) kinds.set(column.name, kind);
    }
  }
  return kinds;
}

function toSqliteValue(value) {
  if (value === undefined) return null;
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (value instanceof Date) return value.toISOString();
  if (value !== null && typeof value === 'object' && !ArrayBuffer.isView(value)) return JSON.stringify(value);
  return value;
}

// A missing file is copied from `seed` when there is one, and built from the schema otherwise.
// Either way it then gets any table added to database/crimguard/ since it was made.
async function openSqlite(file, fallbackReason = null, { seed = null } = {}) {
  if (file !== ':memory:' && !fs.existsSync(file)) {
    if (seed && fs.existsSync(seed) && path.resolve(seed) !== path.resolve(file)) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.copyFileSync(seed, `${file}.tmp`);
      fs.renameSync(`${file}.tmp`, file);
    } else {
      await createSqliteDatabase(file);
    }
  }
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  if (file === ':memory:') db.exec(buildSqliteSchema().sql);
  else upgradeSqliteSchema(db);
  const kinds = columnKinds(db);

  // node:sqlite rows have a null prototype; copy into plain objects like the pg driver returns.
  const normalizeRow = (sqliteRow) => {
    const row = { ...sqliteRow };
    for (const key of Object.keys(row)) {
      const value = row[key];
      if (value === null) continue;
      const kind = kinds.get(key);
      if (kind === 'boolean') row[key] = value === 1;
      else if (kind === 'json' && typeof value === 'string') row[key] = JSON.parse(value);
    }
    return row;
  };

  return {
    dialect: 'sqlite',
    location: file === ':memory:' ? ':memory:' : path.relative(process.cwd(), file) || file,
    fallbackReason,
    async query(sql, params = []) {
      const statement = db.prepare(sql);
      const values = params.map(toSqliteValue);
      if (/^\s*(INSERT|UPDATE|DELETE|REPLACE)\b/i.test(sql) && !/\bRETURNING\b/i.test(sql)) {
        return { rows: [], rowCount: Number(statement.run(...values).changes) };
      }
      const rows = statement.all(...values).map(normalizeRow);
      return { rows, rowCount: rows.length };
    },
    async close() {
      db.close();
    },
  };
}

// --- entry point -----------------------------------------------------------------

async function connectCrimGuard({
  mode = process.env.CRIMGUARD_DB || 'auto',
  databaseUrl = process.env.CRIMGUARD_DATABASE_URL,
  sqlitePath = process.env.CRIMGUARD_SQLITE_PATH || DEFAULT_SQLITE_PATH,
  seedPath = SEED_SQLITE_PATH,
} = {}) {
  if (!MODES.includes(mode)) throw new Error(`CRIMGUARD_DB must be one of: ${MODES.join(', ')}.`);
  if (mode === 'sqlite') return openSqlite(sqlitePath, null, { seed: seedPath });
  try {
    return await openPostgres(databaseUrl);
  } catch (err) {
    if (mode === 'postgres') throw err;
    return openSqlite(sqlitePath, err.message, { seed: seedPath });
  }
}

// One line for startup logs, e.g. "SQLite at database/crimguard.db (CRIMGUARD_DATABASE_URL is not set)".
function describeConnection(db) {
  const name = db.dialect === 'postgres' ? 'PostgreSQL' : 'SQLite';
  return `${name} at ${db.location}${db.fallbackReason ? ` (${db.fallbackReason})` : ''}`;
}

module.exports = { connectCrimGuard, createSqliteDatabase, describeConnection, toSqliteValue, DEFAULT_SQLITE_PATH, SEED_SQLITE_PATH };
