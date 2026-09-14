'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { openDb } = require('../src/db');
const { MIGRATIONS_DIR } = require('../src/db/migrate');
const { PASSWORD, startApp } = require('./helpers');

test('a fresh database gets every table, and reopening it applies nothing twice', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'red-migrate-'));
  const file = path.join(dir, 'red.db');
  try {
    const db = openDb(file);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((row) => row.name);
    assert.deepEqual(tables, ['audit_log', 'auth_throttle', 'projects', 'schema_migrations', 'sessions', 'user_credentials', 'user_profiles', 'users']);
    const versions = db.prepare('SELECT COUNT(*) AS n FROM schema_migrations').get().n;
    assert.equal(versions, fs.readdirSync(MIGRATIONS_DIR).filter((name) => name.endsWith('.sql')).length);
    db.close();

    const again = openDb(file);
    assert.equal(again.prepare('SELECT COUNT(*) AS n FROM schema_migrations').get().n, versions);
    again.close();

    if (process.platform !== 'win32') assert.equal(fs.statSync(file).mode & 0o777, 0o600, 'the database file is private');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a database from before migrations is upgraded in place, and its people can still sign in', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'red-legacy-'));
  const file = path.join(dir, 'red.db');
  try {
    // Recreate what the previous release's openDb() and hashPassword() wrote.
    const legacy = new DatabaseSync(file);
    legacy.exec(`PRAGMA foreign_keys = ON; ${fs.readFileSync(path.join(MIGRATIONS_DIR, '001_baseline.sql'), 'utf8')}`);
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(PASSWORD, salt, 64, { N: 16384, r: 8, p: 1 });
    const scryptHash = ['scrypt', 16384, 8, 1, salt.toString('base64'), key.toString('base64')].join('$');
    legacy.prepare("INSERT INTO users (name, email, password_hash, role) VALUES ('Old Timer', 'old@red.test', ?, 'user')").run(scryptHash);
    legacy.prepare("INSERT INTO projects (owner_id, name, status) VALUES (1, 'Kept project', 'active')").run();
    legacy.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, 1, ?)').run('stale', Date.now() + 1e9);
    legacy.close();

    const app = await startApp({ db: openDb(file) });
    try {
      assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0, 'old sessions are dropped');
      const b = app.browser();
      const login = await b('POST', '/api/login', { email: 'old@red.test', password: PASSWORD });
      assert.equal(login.status, 200, JSON.stringify(login.body));
      assert.deepEqual((await b('GET', '/api/projects')).body.projects.map((p) => p.name), ['Kept project']);
      assert.match(app.db.prepare('SELECT password_hash FROM user_credentials WHERE user_id = 1').get().password_hash, /^\$argon2id\$/);
    } finally {
      app.close();
      app.db.close();
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
