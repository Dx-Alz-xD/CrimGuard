'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { openDb } = require('../src/db');
const { MIGRATIONS_DIR, migrate } = require('../src/db/migrate');
const { PASSWORD, startApp } = require('./helpers');

test('a fresh database gets every table, and reopening it applies nothing twice', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'red-migrate-'));
  const file = path.join(dir, 'red.db');
  try {
    const db = openDb(file);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((row) => row.name);
    assert.deepEqual(tables, [
      'audit_log', 'auth_throttle', 'file_role_grants', 'file_user_grants', 'project_files', 'projects', 'roles',
      'schema_migrations', 'sessions', 'user_credentials', 'user_profiles', 'users',
    ]);
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
      assert.equal(app.db.prepare('SELECT role FROM users WHERE id = 1').get().role, 'employee', "a 'user' became an employee");
    } finally {
      app.close();
      app.db.close();
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('moving to roles rebuilds users without losing anything attached to an account', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'red-roles-'));
  try {
    // A database exactly as the release before roles left it.
    for (const file of fs.readdirSync(MIGRATIONS_DIR).filter((name) => name < '007')) {
      fs.copyFileSync(path.join(MIGRATIONS_DIR, file), path.join(dir, file));
    }
    const db = new DatabaseSync(':memory:');
    db.exec('PRAGMA foreign_keys = ON');
    migrate(db, dir);
    db.exec(`
      INSERT INTO users (id, name, email, role) VALUES (1, 'Ada', 'ada@red.test', 'admin'), (2, 'Uma', 'uma@red.test', 'user');
      INSERT INTO user_credentials (user_id, password_hash) VALUES (1, 'hash-1'), (2, 'hash-2');
      INSERT INTO user_profiles (user_id, job_title) VALUES (1, 'Operations'), (2, 'Design');
      INSERT INTO projects (id, owner_id, name) VALUES (1, 2, 'Kept project');
      INSERT INTO project_files (project_id, name, size, content) VALUES (1, 'notes.txt', 2, x'6869');
      INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at) VALUES ('token', 2, 1, 1, 9000000000000);
      INSERT INTO audit_log (action, actor_id, target_user_id) VALUES ('login.succeeded', 2, 2);
    `);

    migrate(db);

    assert.deepEqual(db.prepare('SELECT id, role FROM users ORDER BY id').all().map((row) => [row.id, row.role]), [[1, 'admin'], [2, 'employee']]);
    for (const [table, count] of [['user_credentials', 2], ['user_profiles', 2], ['projects', 1], ['project_files', 1], ['sessions', 1]]) {
      assert.equal(db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n, count, `${table} survived the rebuild`);
    }
    assert.equal(db.prepare('SELECT actor_id FROM audit_log').get().actor_id, 2, 'the activity log still points at the account');
    assert.equal(db.prepare('SELECT confidentiality FROM project_files').get().confidentiality, 2, 'existing files are Internal');
    assert.equal(db.prepare('PRAGMA foreign_keys').get().foreign_keys, 1, 'foreign keys are switched back on');
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);

    // The rebuilt table still enforces and cascades like the old one.
    assert.throws(() => db.prepare("UPDATE users SET role = 'owner' WHERE id = 1").run(), /FOREIGN KEY/);
    db.prepare('DELETE FROM users WHERE id = 2').run();
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM projects').get().n, 0);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0);
    db.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
