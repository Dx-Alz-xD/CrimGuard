'use strict';

const path = require('node:path');
const { openDb, hasAdmin, ensureAdmin } = require('./db');
const { createApp } = require('./app');

const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;
// In a container or on a hosting platform traffic arrives from outside, so listen on every interface there.
const HOST = process.env.HOST || (isProduction ? '0.0.0.0' : '127.0.0.1');
const DEFAULT_ADMIN_PASSWORD = 'admin12345';

function fail(message) {
  console.error(`Red can't start: ${message}`);
  process.exit(1);
}

async function main() {
  // Default database file stays at the project root (Red/red.db), where it lived before this file moved into src/.
  const db = openDb(process.env.RED_DB || path.join(__dirname, '..', 'red.db'));

  if (!hasAdmin(db)) {
    const password = process.env.RED_ADMIN_PASSWORD;
    if (isProduction && !password) {
      fail('no admin account exists yet. Set RED_ADMIN_EMAIL and RED_ADMIN_PASSWORD so the first admin is not created with a default password.');
    }
    if (password && password.length < 8) fail('RED_ADMIN_PASSWORD must be at least 8 characters.');

    const admin = {
      name: process.env.RED_ADMIN_NAME || 'Red Admin',
      email: (process.env.RED_ADMIN_EMAIL || 'admin@red.local').trim().toLowerCase(),
      password: password || DEFAULT_ADMIN_PASSWORD,
    };
    await ensureAdmin(db, admin);
    console.log(`Created admin account ${admin.email}${password ? '' : ` with the default password "${DEFAULT_ADMIN_PASSWORD}"`}`);
  }

  const maxFileMb = Number(process.env.RED_MAX_FILE_MB);
  const server = createApp({
    db,
    secureCookies: process.env.RED_SECURE_COOKIES === '1',
    maxFileBytes: maxFileMb > 0 ? maxFileMb * 1024 * 1024 : undefined,
  });
  server.listen(PORT, HOST, () => {
    console.log(`Red is running at http://localhost:${server.address().port}`);
  });

  // Platforms send SIGTERM before replacing a container: finish in-flight requests, then close the database.
  const shutdown = (signal) => {
    console.log(`${signal} received, shutting down`);
    server.close(() => {
      db.close();
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
