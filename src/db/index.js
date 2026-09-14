'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { migrate } = require('./migrate');
const { createUserStore } = require('./users');
const { createSessionStore } = require('./sessions');
const { createProjectStore } = require('./projects');
const { createAuditLog } = require('./audit');

const ROLES = ['user', 'admin'];
const STATUSES = ['planning', 'active', 'done'];

function openDb(file) {
  const inMemory = file === ':memory:';
  if (!inMemory) fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });

  const db = new DatabaseSync(file);
  // Defensive mode stops SQL from corrupting the file through PRAGMA writable_schema and similar.
  if (typeof db.enableDefensive === 'function') db.enableDefensive(true);
  db.exec(`
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    PRAGMA trusted_schema = OFF;
    PRAGMA secure_delete = ON;
  `);
  if (!inMemory) {
    db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;');
    // The database holds password hashes: readable by this process's user only.
    fs.chmodSync(file, 0o600);
  }

  migrate(db);
  return db;
}

// Runs fn inside a write transaction. fn must be synchronous: never await while holding the lock.
function transaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function createStores(db) {
  return {
    users: createUserStore(db, { transaction: (fn) => transaction(db, fn) }),
    sessions: createSessionStore(db),
    projects: createProjectStore(db),
    audit: createAuditLog(db),
  };
}

const hasAdmin = (db) => Boolean(db.prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get());

// Creates the first admin when none exists. Returns true if an account was created.
async function ensureAdmin(db, passwords, { name, email, password, mustChangePassword = false }) {
  if (hasAdmin(db)) return false;
  const passwordHash = await passwords.hash(password);
  createStores(db).users.create({ name, email, role: 'admin', passwordHash, mustChangePassword });
  return true;
}

module.exports = { ROLES, STATUSES, openDb, transaction, createStores, hasAdmin, ensureAdmin };
