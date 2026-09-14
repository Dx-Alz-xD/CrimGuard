'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT_DIR = path.join(__dirname, '..');

class ConfigError extends Error {}

const HOUR = 60 * 60 * 1000;
const MINUTE = 60 * 1000;

// How long a session lasts. `admin` covers admins and the CEO: their sessions are shorter because they
// can change other people's access. Every other role uses `user`.
const SESSION_POLICY = Object.freeze({
  user: { idleMs: 24 * HOUR, absoluteMs: 7 * 24 * HOUR },
  admin: { idleMs: 2 * HOUR, absoluteMs: 12 * HOUR },
  maxPerUser: 10,
});

// Largest file a person can upload to a project. RED_MAX_FILE_MB changes it.
const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024;

// Failure limits. Successful sign-ins never count against them.
const RATE_LIMITS = Object.freeze({
  loginPerEmail: { limit: 5, windowMs: 15 * MINUTE, blockMs: 15 * MINUTE },
  loginPerIp: { limit: 50, windowMs: 15 * MINUTE, blockMs: 15 * MINUTE },
  signupPerIp: { limit: 10, windowMs: HOUR, blockMs: HOUR },
  passwordCheckPerUser: { limit: 5, windowMs: 15 * MINUTE, blockMs: 15 * MINUTE },
});

// The pepper comes from RED_PASSWORD_PEPPER or a file named by RED_PASSWORD_PEPPER_FILE (for Docker
// secrets). Outside production, a random one is generated once and kept next to the database.
function loadPepper(env, { isProduction, dbFile }) {
  if (env.RED_PASSWORD_PEPPER) return env.RED_PASSWORD_PEPPER;
  if (env.RED_PASSWORD_PEPPER_FILE) return fs.readFileSync(env.RED_PASSWORD_PEPPER_FILE, 'utf8').trim();
  if (isProduction) {
    throw new ConfigError('RED_PASSWORD_PEPPER is not set. Generate one with `openssl rand -base64 48` and keep it secret: changing or losing it invalidates every password.');
  }

  const file = path.join(path.dirname(dbFile), 'pepper.key');
  try {
    fs.writeFileSync(file, crypto.randomBytes(48).toString('base64'), { flag: 'wx', mode: 0o600 });
    console.log(`Generated a development password pepper at ${file}`);
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }
  return fs.readFileSync(file, 'utf8').trim();
}

function loadConfig(env = process.env) {
  const isProduction = env.NODE_ENV === 'production';
  const dbFile = path.resolve(env.RED_DB || path.join(ROOT_DIR, 'data', 'red.db'));
  fs.mkdirSync(path.dirname(dbFile), { recursive: true, mode: 0o700 });

  const pepper = loadPepper(env, { isProduction, dbFile });
  if (Buffer.byteLength(pepper) < 32) throw new ConfigError('RED_PASSWORD_PEPPER must be at least 32 characters.');

  const adminPassword = env.RED_ADMIN_PASSWORD || '';
  if (adminPassword && adminPassword.length < 12) throw new ConfigError('RED_ADMIN_PASSWORD must be at least 12 characters.');
  const ceoPassword = env.RED_CEO_PASSWORD || '';
  if (ceoPassword && ceoPassword.length < 12) throw new ConfigError('RED_CEO_PASSWORD must be at least 12 characters.');
  const adminEmail = (env.RED_ADMIN_EMAIL || 'admin@red.local').trim().toLowerCase();
  const ceoEmail = (env.RED_CEO_EMAIL || 'ceo@red.local').trim().toLowerCase();
  if (adminEmail === ceoEmail) {
    throw new ConfigError('RED_ADMIN_EMAIL and RED_CEO_EMAIL must be different: the first admin and the CEO are separate accounts.');
  }

  const maxFileMb = env.RED_MAX_FILE_MB ? Number(env.RED_MAX_FILE_MB) : null;
  if (maxFileMb !== null && !(maxFileMb > 0 && maxFileMb <= 100)) {
    throw new ConfigError('RED_MAX_FILE_MB must be a number of megabytes above 0 and at most 100.');
  }

  return {
    isProduction,
    // In a container or on a hosting platform traffic arrives from outside, so listen on every interface there.
    host: env.HOST || (isProduction ? '0.0.0.0' : '127.0.0.1'),
    port: Number(env.PORT) || 3000,
    dbFile,
    pepper,
    secureCookies: env.RED_SECURE_COOKIES === '1',
    trustProxy: env.RED_TRUST_PROXY === '1',
    maxFileBytes: maxFileMb === null ? DEFAULT_MAX_FILE_BYTES : Math.round(maxFileMb * 1024 * 1024),
    admin: {
      name: env.RED_ADMIN_NAME || 'Red Admin',
      email: adminEmail,
      password: adminPassword,
    },
    ceo: {
      name: env.RED_CEO_NAME || 'Red CEO',
      email: ceoEmail,
      password: ceoPassword,
    },
  };
}

module.exports = { ROOT_DIR, ConfigError, SESSION_POLICY, RATE_LIMITS, DEFAULT_MAX_FILE_BYTES, loadConfig };
