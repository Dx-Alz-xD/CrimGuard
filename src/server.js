'use strict';

// Startup: configuration checks, database migrations, the first admin, graceful shutdown.

// Files this process creates (database, WAL, pepper) are private to its user.
process.umask(0o077);

const { ConfigError, loadConfig } = require('./config');
const { openDb, hasAdmin, ensureAdmin } = require('./db');
const { connectCrimGuard, describeConnection } = require('./db/crimguard');
const { createApp } = require('./app');
const { createPasswordHasher } = require('./security/passwords');
const { newPassword } = require('./security/tokens');

function fail(message) {
  console.error(`Red can't start: ${message}`);
  process.exit(1);
}

async function createFirstAdmin(db, config) {
  if (hasAdmin(db)) return;
  const { admin, isProduction } = config;
  if (isProduction && !admin.password) {
    fail('no admin account exists yet. Set RED_ADMIN_EMAIL and RED_ADMIN_PASSWORD so the first admin is not created with a guessable password.');
  }

  // Locally, a random password is printed once and must be replaced at first sign-in.
  const generated = !admin.password;
  const password = admin.password || newPassword();
  await ensureAdmin(db, createPasswordHasher({ pepper: config.pepper }), { ...admin, password, mustChangePassword: generated });
  console.log(generated
    ? `Created admin account ${admin.email} with the one-time password: ${password}\nYou'll be asked to choose a new password when you first sign in.`
    : `Created admin account ${admin.email}`);
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
  await createFirstAdmin(db, config);

  // PostgreSQL when CRIMGUARD_DATABASE_URL is set and reachable, otherwise the SQLite copy.
  // Red's accounts and projects stay in red.db either way, so a failure here doesn't stop the app.
  const crimguard = await connectCrimGuard().catch((err) => {
    console.error(`CrimGuard risk database unavailable: ${err.message}`);
    return null;
  });
  if (crimguard) console.log(`CrimGuard risk database: ${describeConnection(crimguard)}`);

  const server = createApp({ db, pepper: config.pepper, secureCookies: config.secureCookies, trustProxy: config.trustProxy });
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
