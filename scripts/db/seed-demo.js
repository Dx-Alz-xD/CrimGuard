'use strict';

// Fills an empty Red with a company: people, their projects and files, who can see what, and
// enough history for the risk engine to come back with genuinely different scores.
//
//   node scripts/db/seed-demo.js              26 people, ~7 months of history
//   node scripts/db/seed-demo.js --people 12  fewer, for a quicker run
//   node scripts/db/seed-demo.js --days 120   a shorter history
//   node scripts/db/seed-demo.js --reset      delete the seeded accounts first
//
// Everyone gets the same password so any of them can be signed in as; the accounts are all
// @red.local, which is what --reset matches on. Nothing here touches accounts you made yourself.
//
// The point is spread. A console where everybody scores 3 proves nothing, so the population is
// built from six deliberate shapes - quiet, busy-but-explained, slow creep, one loud day,
// leaving-with-a-grudge, shadow-AI user - and the engine is left to find them. The scores are
// never written directly: every number the console shows is the real engine over real events.

const { loadConfig } = require('../../src/config');
const { openDb, createStores } = require('../../src/db');
const { connectCrimGuard, describeConnection } = require('../../src/db/crimguard');
const { createPasswordHasher } = require('../../src/security/passwords');
const { createSubjects } = require('../../src/telemetry/subjects');
const { createEvents } = require('../../src/telemetry/events');
const { createTelemetry } = require('../../src/telemetry');
const { assess } = require('../../src/security/genai');

const PASSWORD = 'demo-password-2026';
const DOMAIN = 'red.local';
const MB = 1024 * 1024;
const DAY = 86400000;

// --- the cast ------------------------------------------------------------------------------------
//
// shape decides how the history is generated, and therefore roughly where the score lands. It is
// never the score itself: the engine still has to find it.

const PEOPLE = [
  // Leadership and admins
  ['Priya Raman', 'employee', 'quiet', { title: 'Head of Corporate Development' }],
  ['Daniel Okafor', 'admin', 'privileged', { title: 'Head of IT' }],
  ['Marta Lis', 'admin', 'quiet', { title: 'Security Lead' }],
  // Finance and legal — the people who hold the confidential material
  ['Wei Chen', 'employee', 'explained', { title: 'Financial Controller' }],
  ['Aisha Bello', 'employee', 'quiet', { title: 'Payroll Manager' }],
  ['Tomás Ferreira', 'employee', 'creep', { title: 'Corporate Counsel' }],
  ['Hannah Vogt', 'employee', 'quiet', { title: 'FP&A Analyst' }],
  // Engineering
  ['Luca Moretti', 'employee', 'shadow_ai', { title: 'Staff Engineer' }],
  ['Sofia Ruiz', 'employee', 'quiet', { title: 'Platform Engineer' }],
  ['Arjun Nair', 'employee', 'busy', { title: 'Data Engineer' }],
  ['Nina Kowalski', 'employee', 'quiet', { title: 'SRE' }],
  ['Peter Osei', 'employee', 'spike', { title: 'Backend Engineer' }],
  ['Yuki Tanaka', 'employee', 'quiet', { title: 'Mobile Engineer' }],
  ['Oscar Lindqvist', 'employee', 'quiet', { title: 'QA Engineer' }],
  // Sales and marketing
  ['Grace Mwangi', 'employee', 'busy', { title: 'Account Executive' }],
  ['Ben Halloran', 'employee', 'leaving', { title: 'Enterprise AE' }],
  ['Clara Dubois', 'employee', 'quiet', { title: 'Marketing Manager' }],
  ['Rohan Mehta', 'employee', 'quiet', { title: 'Sales Engineer' }],
  // People ops
  ['Elena Petrova', 'employee', 'quiet', { title: 'People Partner' }],
  ['Sam Whitfield', 'employee', 'leaving', { title: 'Recruiter' }],
  // Contractors and interns — lower clearance, and the contractor carries a small standing boost
  ['Ivan Horvat', 'intern', 'quiet', { title: 'Engineering Intern' }],
  ['Maya Sharma', 'intern', 'quiet', { title: 'Product Intern' }],
  ['Kofi Mensah', 'intern', 'busy', { title: 'Data Intern' }],
  ['Lena Fischer', 'intern', 'quiet', { title: 'Design Intern' }],
  ['Diego Alvarez', 'employee', 'contractor_creep', { title: 'Contract Integrations Dev' }],
  ['Zoe Bennett', 'employee', 'quiet', { title: 'Office Manager' }],
];

// Projects, and the files inside them. confidentiality is Red's 1-5 scale.
const PROJECTS = [
  ['Acquisition — Northwind', 'Diligence, term sheet and board material for the Northwind deal.', [
    ['northwind-term-sheet.md', 4, 'Indicative offer 240m. Exclusivity to 30 Nov. Do not circulate.'],
    ['northwind-diligence-index.csv', 4, 'area,owner,status\nfinance,Wei Chen,open\nlegal,Tomás Ferreira,open\n'],
    ['board-pack-q3.md', 5, 'Board pack. Deal rationale, dilution model, retention plan.'],
  ]],
  ['Payroll & compensation FY26', 'Bands, bonus multipliers and equity for every employee.', [
    ['comp-bands-fy26.csv', 4, 'band,min,mid,max\nE3,82000,96000,110000\nE4,104000,122000,140000\n'],
    ['bonus-multipliers.csv', 4, 'employee,multiplier\nredacted,1.2\n'],
    ['equity-refresh-plan.md', 5, 'Refresh grants by performance band. Approved by the CEO.'],
  ]],
  ['Platform migration', 'Moving the ingest pipeline off the legacy cluster.', [
    ['migration-runbook.md', 2, 'Cut over region by region. Roll back on error budget burn.'],
    ['schema-diff.sql', 2, 'ALTER TABLE events ADD COLUMN trace_id TEXT;'],
    ['capacity-model.csv', 2, 'region,nodes,headroom\neu-west,24,0.31\n'],
  ]],
  ['Customer accounts', 'Named account plans and renewal forecasts.', [
    ['renewal-forecast-q4.csv', 3, 'account,arr,probability\nAcme,240000,0.7\n'],
    ['account-plan-acme.md', 3, 'Champion: VP Eng. Risk: competing pilot.'],
  ]],
  ['Security programme', 'Controls, findings and the insider-risk rollout.', [
    ['pen-test-findings.md', 4, 'Three highs, all in the legacy admin console. Remediation owner: Daniel.'],
    ['incident-runbook.md', 3, 'Freeze the session, preserve the log, notify the CEO.'],
  ]],
  ['Product roadmap', 'What we are building and when.', [
    ['roadmap-h1.md', 2, 'H1: ingest v2, tenant isolation, audit export.'],
    ['research-notes.md', 1, 'Interview notes from eight design partners.'],
  ]],
  ['Hiring', 'Open roles, scorecards and offers.', [
    ['offer-template.md', 3, 'Standard offer. Equity per band, see comp bands.'],
    ['interview-scorecards.csv', 3, 'candidate,role,score\nredacted,E4,3.4\n'],
  ]],
  ['Vendor contracts', 'Signed agreements and renewal dates.', [
    ['msa-cloudprovider.md', 3, 'Three-year MSA. Auto-renews unless cancelled 90 days out.'],
    ['vendor-list.csv', 2, 'vendor,spend,renews\ncloudprovider,480000,2027-02-01\n'],
  ]],
];

// Deterministic, so two runs of the same seed produce the same company.
function random(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

const pick = (rand, list) => list[Math.floor(rand() * list.length)];

// How many files a person touches on a given day, by shape. `t` is 0 at the start of the history
// and 1 today, so a creep can ramp.
function volumeFor(shape, t, rand, weekday) {
  if (!weekday && rand() > 0.12) return 0; // most people do not work weekends; a few do
  const base = 8 + Math.floor(rand() * 10);
  switch (shape) {
    case 'quiet': return base;
    case 'busy': return base * 3 + Math.floor(rand() * 12);
    case 'privileged': return base * 2;
    case 'explained': return t > 0.85 ? 220 + Math.floor(rand() * 90) : base; // a migration, with a ticket
    case 'creep': return Math.round(base * (1 + 7 * Math.max(0, (t - 0.55) / 0.45)));
    case 'contractor_creep': return Math.round(base * (1 + 5 * Math.max(0, (t - 0.7) / 0.3)));
    case 'spike': return t > 0.985 ? 400 + Math.floor(rand() * 200) : base;
    case 'leaving': return Math.round(base * (1 + 4 * Math.max(0, (t - 0.8) / 0.2)));
    case 'shadow_ai': return base * 2;
    default: return base;
  }
}

function parseArgs(argv) {
  const args = { people: PEOPLE.length, days: 210, reset: false, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (flag === '--people') args.people = Math.min(Math.max(Number(argv[++i]) || 26, 1), PEOPLE.length);
    else if (flag === '--days') args.days = Math.min(Math.max(Number(argv[++i]) || 210, 21), 400);
    else if (flag === '--reset') args.reset = true;
    else if (flag === '--help' || flag === '-h') args.help = true;
    else throw new Error(`Unknown option ${flag}`);
  }
  return args;
}

const emailFor = (name) => `${name.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^a-z]+/g, '.')}@${DOMAIN}`;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(require('node:fs').readFileSync(__filename, 'utf8').split('\n').slice(2, 16).join('\n').replace(/^\/\/ ?/gm, ''));
    return;
  }

  const config = loadConfig();
  const red = openDb(config.dbFile);
  const stores = createStores(red);
  const passwords = createPasswordHasher({ pepper: config.pepper });

  if (args.reset) {
    const removed = red.prepare(`DELETE FROM users WHERE email LIKE '%@${DOMAIN}' AND role NOT IN ('admin', 'ceo')`).run().changes;
    console.log(`Removed ${removed} seeded accounts.\n`);
  }

  const db = await connectCrimGuard();
  console.log(`CrimGuard risk database: ${describeConnection(db)}`);
  const subjects = createSubjects(db);
  const events = createEvents(db);
  const telemetry = createTelemetry(db);

  const cast = PEOPLE.slice(0, args.people);
  const passwordHash = await passwords.hash(PASSWORD);
  const made = [];

  // ---- accounts, projects and files -------------------------------------------------------------
  console.log(`\nCreating ${cast.length} people, their projects and files…`);
  for (const [name, role, shape, extra] of cast) {
    const email = emailFor(name);
    let account = red.prepare('SELECT id, name, email, role FROM users WHERE email = ?').get(email);
    if (!account) {
      account = stores.users.create({ name, email, role, passwordHash, mustChangePassword: false });
      stores.users.updateProfile(account.id, { name, jobTitle: extra.title, organization: 'Red', bio: '' });
    }
    made.push({ ...account, shape, title: extra.title });
  }

  // Projects are spread across the cast, so the dashboard is not one person's.
  const rand = random(20260915);
  const owned = new Map();
  PROJECTS.forEach((spec, index) => {
    const [projectName, description, files] = spec;
    const owner = made[index % made.length];
    const existing = red.prepare('SELECT id FROM projects WHERE owner_id = ? AND name = ?').get(owner.id, projectName);
    const project = existing || stores.projects.create(owner.id, { name: projectName, description, status: 'active' });
    owned.set(projectName, { project, owner });

    for (const [fileName, confidentiality, body] of files) {
      if (red.prepare('SELECT 1 FROM project_files WHERE project_id = ? AND name = ?').get(project.id, fileName)) continue;
      const file = stores.files.create(project.id, { name: fileName, type: 'text/plain', content: Buffer.from(`${body}\n`) });
      // Everything above Internal is set deliberately, and shared with the people who need it.
      const audience = made.filter((person) => person.shape !== 'quiet').slice(0, 3).map((person) => person.id);
      stores.files.setAccess(file.id, {
        confidentiality, roleIds: [], userIds: confidentiality >= 3 ? audience : [], grantedBy: owner.id,
      });
    }
  });
  console.log(`  ${PROJECTS.length} projects, ${PROJECTS.reduce((n, p) => n + p[2].length, 0)} files`);

  // ---- history ---------------------------------------------------------------------------------
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  const dates = [];
  for (let back = args.days - 1; back >= 0; back -= 1) {
    dates.push(new Date(today.getTime() - back * DAY));
  }

  console.log(`\nWriting ${args.days} days of events for each person…`);
  for (const person of made) {
    const crimUserId = await subjects.forUser(person);
    const personRand = random(person.id * 7919);
    const deviceId = await subjects.forDevice(crimUserId, `seed-${person.id}-laptop`, { os: 'Win32' });
    const resources = [];
    for (const { project } of owned.values()) {
      resources.push(await subjects.forResource('project', project.id, project.name));
    }

    let written = 0;
    for (const [index, date] of dates.entries()) {
      const t = index / Math.max(1, dates.length - 1);
      const weekday = date.getUTCDay() !== 0 && date.getUTCDay() !== 6;
      const volume = volumeFor(person.shape, t, personRand, weekday);
      if (!volume) continue;

      // Work happens in office hours, except for the shapes that deliberately do not.
      const lateShift = person.shape === 'creep' || person.shape === 'leaving' ? 4 : 0;
      const startHour = 8 + lateShift + Math.floor(personRand() * 3);
      const at = (n) => new Date(date.getTime() + (startHour * 3600 + n * 47) * 1000).toISOString();

      await events.auth({
        userId: crimUserId, deviceId, eventType: 'login_success', occurredAt: at(0),
        ip: '198.51.100.24', countryCode: 'GB', userAgent: 'Mozilla/5.0',
      });

      for (let n = 0; n < volume; n += 1) {
        await events.fileAccess({
          userId: crimUserId, deviceId, resourceId: pick(personRand, resources),
          action: personRand() > 0.82 ? 'download' : 'read',
          occurredAt: at(n + 1), bytes: Math.round((0.1 + personRand()) * MB),
          filePath: `file-${n}.dat`,
        });
        written += 1;
      }

      // Someone on their way out, in the last fortnight, taking rather more than they put back.
      if (person.shape === 'leaving' && t > 0.93) {
        await events.transfer({
          userId: crimUserId, deviceId, channel: 'download', occurredAt: at(volume + 2),
          bytes: Math.round(40 * MB * personRand()), fileName: 'archive.zip',
          destination: 'browser download', isCompressed: true, sensitivity: 'confidential',
        });
      }

      // The shadow-AI user pastes work into a model most days, and more of it lately.
      if (person.shape === 'shadow_ai' && weekday && personRand() > 0.45) {
        const chars = Math.round(1500 + personRand() * 9000 * (0.4 + t));
        const destination = pick(personRand, ['chatgpt.com', 'claude.ai', 'gemini.google.com', 'perplexity.ai']);
        const verdict = assess({ destination, chars, sensitivity: 3 });
        await events.clipboard({
          userId: crimUserId, deviceId, occurredAt: at(volume + 3), charCount: chars,
          sourceApp: 'red', destinationApp: destination,
          classification: 'confidential', detectedPatterns: chars > 8000 ? ['source_code'] : [],
        });
        await subjects.forExternalDomain(destination, verdict.category);
      }
    }
    process.stdout.write(`  ${person.name.padEnd(20)} ${person.shape.padEnd(18)} ${written} events\n`);
  }

  // ---- HR context, which the amplifier runs on --------------------------------------------------
  console.log('\nRecording HR context…');
  for (const person of made) {
    const crimUserId = await subjects.forUser(person);
    if (person.shape === 'leaving') {
      const leaving = new Date(Date.now() + 9 * DAY).toISOString().slice(0, 10);
      await db.query("UPDATE users SET termination_date = ?, employment_status = 'notice_period' WHERE id = ?", [leaving, crimUserId]);
      await db.query(
        "INSERT INTO hr_events (user_id, event_type, effective_date, recorded_at, source_system) VALUES (?, 'resignation_notice', ?, ?, 'seed')",
        [crimUserId, leaving, new Date().toISOString()],
      );
      stores.departures.setState(person.id, { terminationDate: leaving });
      console.log(`  ${person.name} is leaving on ${leaving}`);
    }
    if (person.shape === 'contractor_creep') {
      await db.query("UPDATE users SET employment_type = 'contractor' WHERE id = ?", [crimUserId]);
      console.log(`  ${person.name} is a contractor`);
    }
    if (person.shape === 'creep') {
      await db.query(
        "INSERT INTO hr_events (user_id, event_type, effective_date, recorded_at, is_negative, source_system) VALUES (?, 'performance_review', ?, ?, true, 'seed')",
        [crimUserId, new Date(Date.now() - 20 * DAY).toISOString().slice(0, 10), new Date().toISOString()],
      );
      console.log(`  ${person.name} had a poor review`);
    }
    // The busy-but-explained one has a ticket covering the migration, which is what keeps the
    // score down: the engine is supposed to tell a sanctioned spike from an unexplained one.
    if (person.shape === 'explained') {
      await db.query(
        `INSERT INTO tickets (org_id, external_key, title, ticket_type, status, is_approved, opened_at, due_at, expected_daily_file_volume)
         VALUES (1, 'MIG-204', 'Legacy cluster migration', 'migration', 'in_progress', true, ?, ?, 300)`,
        [new Date(Date.now() - 40 * DAY).toISOString(), new Date(Date.now() + 20 * DAY).toISOString()],
      ).catch(() => {});
      console.log(`  ${person.name} has an approved migration ticket`);
    }
  }

  // ---- score every day, with the real engine ----------------------------------------------------
  console.log(`\nScoring ${dates.length} days with the risk engine (this is the slow part)…`);
  let scored = 0;
  for (const date of dates) {
    const day = date.toISOString().slice(0, 10);
    const result = await telemetry.runDay(day);
    scored += result.scored;
    if (day.endsWith('-01')) process.stdout.write(`  ${day}\n`);
  }

  // ---- what came out ----------------------------------------------------------------------------
  const { rows } = await db.query(
    `SELECT u.full_name, r.final_score, r.risk_level, r.scenario
     FROM risk_scores r
     JOIN users u ON u.id = r.user_id
     WHERE r.id IN (SELECT MAX(id) FROM risk_scores GROUP BY user_id)
     ORDER BY r.final_score DESC`,
  );
  console.log(`\n${scored} day-scores written. Where everyone landed:\n`);
  for (const row of rows) {
    const score = Number(row.final_score);
    console.log(`  ${String(row.full_name).padEnd(20)} ${score.toFixed(1).padStart(6)}  ${String(row.risk_level).padEnd(9)} ${row.scenario || ''}`);
  }

  console.log(`\nEveryone signs in with: ${PASSWORD}`);
  console.log(`For example: ${emailFor(cast[0][0])}\n`);

  red.close();
  await db.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
