'use strict';

// Startup: configuration checks, database migrations, the first admin and the CEO, graceful shutdown.

// Files this process creates (database, WAL, pepper) are private to its user.
process.umask(0o077);

const { ConfigError, loadConfig } = require('./config');
const { openDb, hasRole, ensureAccount } = require('./db');
const { connectCrimGuard, describeConnection } = require('./db/crimguard');
const { DuplicateEmailError } = require('./db/users');
const { createApp } = require('./app');
const { createPasswordHasher } = require('./security/passwords');
const { newPassword } = require('./security/tokens');

function fail(message) {
  console.error(`Red can't start: ${message}`);
  process.exit(1);
}

const FIRST_ACCOUNTS = {
  admin: { env: 'RED_ADMIN', title: 'admin', who: 'the first admin' },
  ceo: { env: 'RED_CEO', title: 'CEO', who: 'the CEO' },
};

// The first admin and the CEO are created the same way, when nobody holds the role yet: from the
// RED_ADMIN_* or RED_CEO_* variables, or locally with a random password that is printed once and must
// be replaced at first sign-in.
async function createFirstAccount(db, config, role) {
  if (hasRole(db, role)) return;
  const account = config[role];
  const { env, title, who } = FIRST_ACCOUNTS[role];
  if (config.isProduction && !account.password) {
    fail(`no ${title} account exists yet. Set ${env}_EMAIL and ${env}_PASSWORD so ${who} is not created with a guessable password.`);
  }

  const generated = !account.password;
  const password = account.password || newPassword();
  try {
    await ensureAccount(db, createPasswordHasher({ pepper: config.pepper }), role, { ...account, password, mustChangePassword: generated });
  } catch (err) {
    if (err instanceof DuplicateEmailError) fail(`${account.email} already belongs to another account. Set ${env}_EMAIL to a different address for ${who}.`);
    throw err;
  }
  console.log(generated
    ? `Created ${title} account ${account.email} with the one-time password: ${password}\nYou'll be asked to choose a new password when you first sign in.`
    : `Created ${title} account ${account.email}`);
}

async function main() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) fail(err.message);
    throw err;
  }

  const db = openDb(config.dbFile);
  await createFirstAccount(db, config, 'admin');
  await createFirstAccount(db, config, 'ceo');

  // PostgreSQL when CRIMGUARD_DATABASE_URL is set and reachable, otherwise the SQLite copy.
  // Red's accounts and projects stay in red.db either way, so a failure here doesn't stop the app.
  const crimguard = await connectCrimGuard().catch((err) => {
    console.error(`CrimGuard risk database unavailable: ${err.message}`);
    return null;
  });
  if (crimguard) console.log(`CrimGuard risk database: ${describeConnection(crimguard)}`);

  const server = createApp({
    db,
    crimguard,
    pepper: config.pepper,
    secureCookies: config.secureCookies,
    trustProxy: config.trustProxy,
    maxFileBytes: config.maxFileBytes,
  });
  server.listen(config.port, config.host, () => {
    console.log(`Red is running at http://localhost:${server.address().port}`);
  });

  // Platforms send SIGTERM before replacing a container: finish in-flight requests, then close the databases.
  const shutdown = (signal) => {
    console.log(`${signal} received, shutting down`);
    server.close(async () => {
      db.close();
      await crimguard?.close();
      process.exit(0);
    });
    server.closeIdleConnections();
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
