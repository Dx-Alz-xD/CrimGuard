'use strict';

// Shows which CrimGuard risk database this machine uses, and what's in it: npm run db:status

const { connectCrimGuard, describeConnection } = require('../../src/db/crimguard');

const OBJECT_COUNTS = {
  postgres: `SELECT count(*) FILTER (WHERE table_type = 'BASE TABLE') AS tables,
                    count(*) FILTER (WHERE table_type = 'VIEW') AS views
             FROM information_schema.tables WHERE table_schema = 'public'`,
  sqlite: `SELECT sum(type = 'table') AS tables, sum(type = 'view') AS views
           FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'`,
};

async function main() {
  const db = await connectCrimGuard();
  try {
    const count = async (table) => (await db.query(`SELECT count(*) AS n FROM ${table}`)).rows[0].n;
    const [{ tables, views }] = (await db.query(OBJECT_COUNTS[db.dialect])).rows;

    console.log(`CrimGuard risk database: ${describeConnection(db)}`);
    console.log(`  ${tables} tables, ${views} views, ${await count('feature_catalog')} risk variables in the catalog`);
    console.log(
      `  ${await count('users')} people, ${await count('risk_feature_snapshot')} daily snapshots, ` +
        `${await count('risk_scores')} risk scores, ${await count('alerts')} alerts`,
    );
  } finally {
    await db.close();
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
