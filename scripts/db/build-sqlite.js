'use strict';

// Rebuilds database/crimguard.db, the SQLite copy of the CrimGuard risk database that is
// committed to the repo for anyone without PostgreSQL. Commit the new file to share it.
//
//   npm run db:sqlite                     tables, views and the 100-variable catalog
//   npm run db:sqlite -- --from-postgres  also copy every row from CRIMGUARD_DATABASE_URL,
//                                         so people on SQLite see the same data

const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { buildSqliteSchema } = require('../../src/db/sqlite-schema');
const { connectCrimGuard, createSqliteDatabase, toSqliteValue, SEED_SQLITE_PATH } = require('../../src/db/crimguard');

async function copyFromPostgres(file) {
  const source = await connectCrimGuard({ mode: 'postgres' });
  const target = new DatabaseSync(file);
  const { tables } = buildSqliteSchema();
  try {
    // Self-references such as users.manager_id can point at rows copied later,
    // so foreign keys are checked once, after everything is in.
    target.exec('PRAGMA foreign_keys = OFF; BEGIN;');
    for (const { name } of [...tables].reverse()) target.exec(`DELETE FROM ${name}`); // drops the seeded catalog

    for (const { name, columns } of tables) {
      const list = columns.map((column) => column.name);
      const insert = target.prepare(`INSERT INTO ${name} (${list.join(', ')}) VALUES (${list.map(() => '?').join(', ')})`);
      const { rows } = await source.query(`SELECT ${list.join(', ')} FROM ${name}`);
      for (const row of rows) insert.run(...list.map((column) => toSqliteValue(row[column])));
      if (rows.length) console.log(`  ${name}: ${rows.length} rows`);
    }

    const broken = target.prepare('PRAGMA foreign_key_check').all();
    if (broken.length) throw new Error(`${broken.length} copied rows reference missing rows, e.g. ${JSON.stringify(broken[0])}`);
    target.exec('COMMIT;');
  } finally {
    target.close();
    await source.close();
  }
}

async function main() {
  const fromPostgres = process.argv.includes('--from-postgres');
  const file = path.resolve(process.env.CRIMGUARD_SQLITE_PATH || SEED_SQLITE_PATH);
  if (fromPostgres) console.log('Copying rows from PostgreSQL:');
  await createSqliteDatabase(file, fromPostgres ? copyFromPostgres : undefined);
  console.log(`Built ${path.relative(process.cwd(), file)}${fromPostgres ? ' with the PostgreSQL data' : ''}. Commit it to share it.`);
}

main().catch((err) => {
  console.error(`Couldn't build the SQLite database: ${err.message}`);
  process.exit(1);
});
