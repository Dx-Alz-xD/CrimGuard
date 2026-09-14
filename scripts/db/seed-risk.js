'use strict';

// Fills the risk database with a history for one real Red account, so the console and the
// live panel have something to show without waiting months for it to accumulate.
//
//   node scripts/db/seed-risk.js                     the first admin, 210 days
//   node scripts/db/seed-risk.js --email a@b.c       a particular account
//   node scripts/db/seed-risk.js --days 120          a longer history
//   node scripts/db/seed-risk.js --profile spike     one loud day instead of a slow creep
//   node scripts/db/seed-risk.js --reset             clear this account's history first
//
// The shape is the deck's Case B: four months of ordinary work, then a slow creep over the
// last three from ~15 to ~70 files a day, with nothing on file to explain it - the pattern a
// 3-sigma rule misses because the rolling baseline absorbs it as it goes. The default history
// is long enough that the anchored window the drift detector compares against (180 to 90 days
// back) still falls in the quiet period. `--profile spike` instead leaves the baseline flat
// and puts everything into the last day.
//
// Events are written with real past timestamps, exactly as the collector would have produced
// them, and then the ordinary aggregation and scoring run over each day in turn.

const path = require('node:path');
const { loadConfig } = require('../../src/config');
const { openDb } = require('../../src/db');
const { connectCrimGuard, describeConnection } = require('../../src/db/crimguard');
const { createSubjects } = require('../../src/telemetry/subjects');
const { createEvents } = require('../../src/telemetry/events');
const { createTelemetry } = require('../../src/telemetry');

const MB = 1024 * 1024;

function parseArgs(argv) {
  const args = { days: 210, profile: 'creep', email: null, reset: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === '--email') args.email = argv[++i];
    else if (flag === '--days') args.days = Math.min(Math.max(Number(argv[++i]) || 210, 14), 400);
    else if (flag === '--profile') args.profile = argv[++i];
    else if (flag === '--reset') args.reset = true;
    else if (flag === '--help' || flag === '-h') args.help = true;
    else throw new Error(`Unknown option ${flag}`);
  }
  if (!['creep', 'spike', 'quiet'].includes(args.profile)) throw new Error('--profile must be creep, spike or quiet');
  return args;
}

// Seeded so a rerun produces the same history.
function random(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

const dayOf = (daysAgo) => new Date(Date.now() - daysAgo * 86400000).toISOString().slice(0, 10);
const at = (date, hour, minute = 0) =>
  new Date(`${date}T00:00:00.000Z`).getTime() + hour * 3600000 + minute * 60000;
const iso = (ms) => new Date(ms).toISOString();
const isWeekend = (date) => [0, 6].includes(new Date(`${date}T00:00:00Z`).getUTCDay());

// How busy a day is, and how much of it looks like data leaving.
function shapeFor(profile, daysAgo, total) {
  // The drift detector compares the last fortnight against a window 180-90 days back, so the
  // creep has to be shorter than that for there to be a clean anchor period behind it.
  const creepDays = Math.min(85, Math.floor(total / 2));
  if (profile === 'quiet') return { files: 14, downloadMb: 0, afterHours: false };

  if (profile === 'spike') {
    if (daysAgo > 0) return { files: 15, downloadMb: 0.2, afterHours: false };
    return { files: 240, downloadMb: 180, afterHours: true, renameThenExport: true };
  }

  // creep: flat, then a ramp that never jumps. Each term is deliberately gradual - the whole
  // point of Case B is that no single day looks wrong.
  if (daysAgo > creepDays) return { files: 15, downloadMb: 0.3, afterHours: false };
  const progress = 1 - daysAgo / creepDays; // 0 at the start of the creep, 1 today
  return {
    files: Math.round(15 + 55 * progress),
    downloadMb: Number((0.3 + 9 * progress ** 2.2).toFixed(2)),
    afterHours: progress > 0.7,
    renameThenExport: progress > 0.88,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(require('node:fs').readFileSync(__filename, 'utf8').split('\n').slice(2, 18).join('\n').replace(/^\/\/ ?/gm, ''));
    return;
  }

  const config = loadConfig();
  const red = openDb(config.dbFile);
  const account = args.email
    ? red.prepare('SELECT id, name, email, role FROM users WHERE email = ?').get(args.email.trim().toLowerCase())
    : red.prepare("SELECT id, name, email, role FROM users WHERE role = 'admin' ORDER BY id LIMIT 1").get();

  if (!account) {
    console.error(args.email
      ? `No Red account with the email ${args.email}. Start the server once, or sign up, then run this again.`
      : 'No accounts in red.db yet. Start the server once so the first admin is created, then run this again.');
    process.exitCode = 1;
    return;
  }

  const db = await connectCrimGuard();
  console.log(`CrimGuard risk database: ${describeConnection(db)}`);
  console.log(`Seeding ${args.days} days of "${args.profile}" history for ${account.name} <${account.email}>\n`);

  const subjects = createSubjects(db);
  const events = createEvents(db);
  const telemetry = createTelemetry(db);
  const userId = await subjects.forUser(account);

  if (args.reset) {
    const tables = ['file_access_events', 'data_transfer_events', 'clipboard_events', 'auth_events', 'endpoint_events',
      'biometric_samples', 'privilege_events', 'network_events', 'communication_events', 'user_sessions',
      'honeytoken_triggers', 'anomalies', 'risk_scores'];
    for (const table of tables) await db.query(`DELETE FROM ${table} WHERE user_id = ?`, [userId]);
    await db.query('DELETE FROM risk_feature_snapshot WHERE user_id = ?', [userId]);
    await db.query('DELETE FROM alerts WHERE user_id = ?', [userId]);
    console.log('Cleared the previous history for this account.');
  }

  // A handful of resources to move between, so files_accessed_count and
  // distinct_resource_types_touched have something real to count.
  const projectIds = [];
  for (let i = 1; i <= 80; i++) projectIds.push(await subjects.forResource('project', 9000 + i, `Project ${i}`));
  const directory = await subjects.forResource('directory');
  const dashboard = await subjects.forResource('page', 'dashboard', '/dashboard');

  const rand = random(account.id * 7919 + args.days);
  const device = `seed-${account.id}-laptop`;
  const deviceId = await subjects.forDevice(userId, device, { os: 'Win32' });
  const ip = '198.51.100.24';

  let written = 0;
  const dates = [];

  for (let daysAgo = args.days; daysAgo >= 0; daysAgo--) {
    const date = dayOf(daysAgo);
    const shape = shapeFor(args.profile, daysAgo, args.days);
    // Weekends stay quiet until the creep is well under way, which is what makes the
    // eventual weekend work stand out.
    if (isWeekend(date) && !(shape.afterHours && rand() < 0.5)) continue;
    dates.push(date);

    const startHour = shape.afterHours && rand() < 0.6 ? 20 + rand() * 2 : 8.5 + rand();
    const startedAt = at(date, Math.floor(startHour), Math.floor((startHour % 1) * 60));
    const length = (shape.afterHours ? 5 : 7.5) + rand() * 2;
    const endedAt = startedAt + length * 3600000;

    const sessionRef = `seed:${date}`;
    const sessionId = await events.startSession({
      userId, deviceId, sessionRef, startedAt: iso(startedAt), ip, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    });
    await db.query('UPDATE user_sessions SET ended_at = ?, city = ? WHERE id = ?', [iso(endedAt), 'Europe/Berlin', sessionId]);
    await events.auth({
      userId, sessionId, deviceId, eventType: 'login_success', occurredAt: iso(startedAt),
      ip, city: 'Europe/Berlin', userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    });
    // The occasional mistyped password, so failed_login_attempt_count has a baseline above zero.
    if (rand() < 0.12) {
      await events.auth({ userId, deviceId, eventType: 'login_failure', occurredAt: iso(startedAt - 40000), ip });
    }
    written += 2;

    await events.fileAccess({
      userId, sessionId, deviceId, resourceId: dashboard, action: 'read', occurredAt: iso(startedAt + 5000), filesInBatch: 6,
    });

    // The day's file activity, spread across the session.
    for (let i = 0; i < shape.files; i++) {
      const when = startedAt + Math.floor(rand() * (endedAt - startedAt));
      const resourceId = projectIds[Math.floor(rand() * projectIds.length)];
      const roll = rand();
      const action = roll < 0.82 ? 'read' : roll < 0.95 ? 'write' : 'delete';
      await events.fileAccess({ userId, sessionId, deviceId, resourceId, action, occurredAt: iso(when), bytes: Math.floor(2000 + rand() * 60000) });
      written += 1;
    }

    // Looking through other people's records, and searching for the sorts of terms that make
    // unusual_search_query_count mean something.
    if (account.role === 'admin' && rand() < 0.5) {
      await events.fileAccess({ userId, sessionId, deviceId, resourceId: directory, action: 'read', occurredAt: iso(startedAt + 600000), filesInBatch: 5 });
      if (shape.afterHours && rand() < 0.6) {
        const term = ['salary', 'password reset', 'compensation', 'api key'][Math.floor(rand() * 4)];
        await events.fileAccess({ userId, sessionId, deviceId, resourceId: directory, action: 'search', occurredAt: iso(startedAt + 900000), searchQuery: term });
      }
    }

    // Data leaving.
    if (shape.downloadMb > 0.01) {
      const bytes = Math.floor(shape.downloadMb * MB * (0.8 + rand() * 0.4));
      const exportAt = endedAt - 1200000;
      if (shape.renameThenExport) {
        await events.fileAccess({
          userId, sessionId, deviceId, resourceId: projectIds[3], action: 'rename',
          occurredAt: iso(exportAt - 900000), filePath: 'archive-2024', previousPath: 'Customer contracts',
        });
      }
      await events.transfer({
        userId, deviceId, resourceId: directory, channel: 'download', occurredAt: iso(exportAt),
        bytes, fileName: 'red-projects.json', destination: 'browser download',
        renamedBeforeExport: Boolean(shape.renameThenExport), sensitivity: 'internal',
      });
      await events.fileAccess({ userId, sessionId, deviceId, resourceId: directory, action: 'download', occurredAt: iso(exportAt), bytes, filesInBatch: shape.files });
      written += 2;
    }

    // Bytes served, for bandwidth_usage_spike.
    await events.network({ userId, deviceId, occurredAt: iso(startedAt + 60000), ip, destinationDomain: 'red', bytesOut: Math.floor((0.4 + shape.files * 0.03) * MB) });

    // Clipboard and printing pick up as the creep goes on.
    const copies = shape.afterHours ? Math.floor(rand() * 5) : Math.floor(rand() * 2);
    for (let i = 0; i < copies; i++) {
      const big = shape.afterHours && rand() < 0.5;
      await events.clipboard({
        userId, deviceId, occurredAt: iso(startedAt + Math.floor(rand() * (endedAt - startedAt))),
        charCount: big ? 8000 + Math.floor(rand() * 30000) : Math.floor(rand() * 900),
        sourceApp: 'red', destinationApp: 'external',
        detectedPatterns: big && rand() < 0.4 ? ['api_key'] : [],
        classification: big ? 'confidential' : null,
      });
      written += 1;
    }
    if (shape.afterHours && rand() < 0.35) {
      await events.endpoint({
        userId, deviceId, eventType: 'print_job', occurredAt: iso(endedAt - 600000), appName: 'red-web',
        isSanctionedApp: true, details: { pages: 4 + Math.floor(rand() * 20), sensitive: true },
      });
      written += 1;
    }
    if (shape.afterHours && rand() < 0.2) {
      await events.endpoint({ userId, deviceId, eventType: 'screenshot', occurredAt: iso(endedAt - 300000), appName: 'red-web', isSanctionedApp: true, details: {} });
    }

    // Typing and pointer rhythm, one window an hour, drifting a little day to day so the
    // biometric baselines are a distribution rather than a constant.
    for (let hour = 0; hour < Math.floor(length); hour++) {
      await events.biometric({
        userId, sessionId, deviceId, windowStart: iso(startedAt + hour * 3600000), windowSeconds: 3600,
        keystrokeIntervalMeanMs: 150 + rand() * 40 + (shape.afterHours ? 30 : 0),
        keystrokeIntervalStdMs: 55 + rand() * 25,
        keyDwellMeanMs: 85 + rand() * 20,
        mouseVelocityMeanPxS: 520 + rand() * 180 + (shape.afterHours ? 160 : 0),
        mouseVelocityStdPxS: 210 + rand() * 90,
        scrollEvents: Math.floor(20 + rand() * 60),
        scrollVelocityMean: 90 + rand() * 60,
        appSwitches: Math.floor(3 + rand() * 10),
        idleSeconds: Math.floor(rand() * (shape.afterHours ? 300 : 900)),
        openWindowCount: 1 + Math.floor(rand() * 3),
        copyPasteEvents: copies,
      });
      written += 1;
    }

    await events.endSession({ sessionRef, endedAt: iso(endedAt) });
  }

  console.log(`Wrote ${written} events across ${dates.length} active days.`);
  console.log('Aggregating and scoring each day…');

  let scored = 0;
  let planted = 0;
  for (const date of dates) {
    const result = await telemetry.runDay(date);
    scored += result.scored;
    planted += result.planted || 0;
  }
  // Today, so the panel has something even if today had no seeded activity.
  const todayRun = await telemetry.runDay(dayOf(0));
  planted += todayRun.planted || 0;

  const report = await telemetry.report.forRedUser(account.id);
  const filled = report ? report.features.filter((feature) => feature.value !== null).length : 0;
  const recent = (report?.history || []).filter((row) => row.final_score !== null).slice(-8);

  console.log(`\nScored ${scored} days. Latest snapshot ${report?.date ?? 'none'}: ${filled} of 100 variables have a value.`);
  if (recent.length) {
    console.log('\nLast few days:');
    for (const row of recent) {
      console.log(`  ${row.snapshot_date}  ${String(Number(row.final_score).toFixed(1)).padStart(6)}  ${row.risk_level}${row.scenario ? `  ${row.scenario.replace(/_/g, ' ')}` : ''}`);
    }
  }
  if (planted) console.log(`\nA decoy project was planted for this account (score is at or above ${telemetry.honeytokens.plantScore}).`);
  console.log(`\nSign in as ${account.email} and open the Risk button in the bottom-left corner.`);
  if (account.role === 'admin') console.log('The full console is at /admin/risk.');

  await db.close();
  red.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

module.exports = { shapeFor, parseArgs };
