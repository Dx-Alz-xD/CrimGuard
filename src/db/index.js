'use strict';

const { DatabaseSync } = require('node:sqlite');
const { hashPassword } = require('../security/passwords');

const ROLES = ['user', 'admin'];
const STATUSES = ['planning', 'active', 'done'];

const sqlList = (values) => values.map((value) => `'${value}'`).join(', ');

function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY,
      name          TEXT NOT NULL,
      email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN (${sqlList(ROLES)})),
      created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS projects (
      id          INTEGER PRIMARY KEY,
      owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      status      TEXT NOT NULL DEFAULT 'planning' CHECK (status IN (${sqlList(STATUSES)})),
      created_at  TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS projects_by_owner ON projects(owner_id);
  `);
  return db;
}

const hasAdmin = (db) => Boolean(db.prepare("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get());

// Creates the first admin when none exists. Returns true if an account was created.
async function ensureAdmin(db, { name, email, password }) {
  if (hasAdmin(db)) return false;
  const passwordHash = await hashPassword(password);
  db.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')").run(name, email, passwordHash);
  return true;
}

module.exports = { ROLES, STATUSES, openDb, hasAdmin, ensureAdmin };
