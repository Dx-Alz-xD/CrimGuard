'use strict';

// The bridge between the Red website and the CrimGuard risk database.
//
// Routes call the on* methods, which return immediately: the work goes onto a serial queue and
// happens behind the request. Telemetry must never slow a page down or fail one, so every job
// is wrapped - if the risk database is unavailable, Red carries on and the events are lost
// rather than the request.
//
// Nightly (and every quarter of an hour, so the console is current) `runDay` aggregates the
// raw events into the 100 variables and scores them.

const crypto = require('node:crypto');
const { isPrivileged } = require('../security/access');
const { createSubjects } = require('./subjects');
const { createEvents } = require('./events');
const { parseBatch } = require('./ingest');
const { featuresFor } = require('./features');
const { featureLayout, writeSnapshot } = require('./snapshots');
const { createScorer, loadCatalog, loadOrgSettings } = require('./scoring');
const { classifyText } = require('./patterns');
const { createHoneytokens } = require('./honeytokens');
const { locate } = require('./geo');
const { coverage, assertCoversCatalog, summary: coverageSummary } = require('./coverage');

const MAX_QUEUE = 500;
const MAX_LOGGED_ERRORS = 5;

// The Red session token hash keys rows in red.db, so a one-way derivation of it is what goes
// into the risk database instead.
const sessionRef = (tokenHash) =>
  (tokenHash ? crypto.createHash('sha256').update(`telemetry:${tokenHash}`).digest('hex').slice(0, 32) : null);

const today = () => new Date().toISOString().slice(0, 10);

// Red's roles, as the peer groups the engine compares people within. A role the CEO adds is named
// after itself. 'user' is the role everyone but admins had before roles had clearance.
const ROLE_NAMES = { ceo: 'Red CEO', admin: 'Red admin', employee: 'Red employee', intern: 'Red intern', user: 'Red user' };

const median = (values) => {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = sorted.length >> 1;
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};

// What each variable usually looks like for this person: the median of recent days for a
// number, and how often it was true for a flag. This is what turns a bare value in the panel
// into "26 files today, 41 is normal for you".
function baselinesFor(catalog, rows) {
  const usual = {};
  for (const meta of catalog) {
    const seen = rows.map((row) => row[meta.key]).filter((value) => value !== null && value !== undefined);
    if (!seen.length) {
      usual[meta.key] = { usual: null, baselineDays: 0 };
      continue;
    }
    usual[meta.key] = meta.valueType === 'flag'
      // For a flag, "usual" is the share of days it was set: a first-ever weekend login is
      // evidence, but for someone who works most weekends it is nothing.
      ? { usual: seen.filter(Boolean).length / seen.length, baselineDays: seen.length }
      : { usual: median(seen.filter((value) => typeof value === 'number')), baselineDays: seen.length };
  }
  return usual;
}

function createTelemetry(db, {
  onError = (err) => console.error('Telemetry:', err.message),
  honeytokenScore = Number(process.env.RED_HONEYTOKEN_SCORE) || undefined,
  onHoneytokenTrip = null,
  // Called with { crimUserId, redUserId, date, result } after a person's day is scored, so a
  // response (src/protection/) can act on the new score straight away.
  onScored = null,
} = {}) {
  if (!db) return createNoop();

  const subjects = createSubjects(db);
  const events = createEvents(db);
  const honeytokens = createHoneytokens(db, { subjects, events, plantScore: honeytokenScore, onTrip: onHoneytokenTrip });

  let ready = null;
  let layout = null;
  let scorer = null;
  let catalog = null;

  // Loaded once: the catalog, the per-org overrides and the engine built from them.
  function initialize() {
    ready ||= (async () => {
      catalog = await loadCatalog(db);
      assertCoversCatalog(catalog.map((meta) => meta.key));
      const { rows } = await db.query('SELECT feature_key, category FROM feature_catalog');
      layout = featureLayout(rows);
      const orgId = await subjects.organization();
      scorer = createScorer(db, { catalog, orgSettings: await loadOrgSettings(db, orgId) });
    })();
    return ready;
  }

  // --- the queue -------------------------------------------------------------------

  let tail = Promise.resolve();
  let depth = 0;
  let dropped = 0;
  let logged = 0;
  // user:date -> when that day was last recomputed, so polling panels don't rebuild it each time.
  const refreshed = new Map();

  function enqueue(job) {
    if (depth >= MAX_QUEUE) {
      dropped += 1;
      return tail;
    }
    depth += 1;
    tail = tail.then(async () => {
      try {
        await initialize();
        await job();
      } catch (err) {
        if (logged < MAX_LOGGED_ERRORS) {
          logged += 1;
          onError(err);
          if (logged === MAX_LOGGED_ERRORS) onError(new Error('further telemetry errors will not be logged'));
        }
      } finally {
        depth -= 1;
      }
    });
    return tail;
  }

  // Waits for everything queued so far. Used by the tests and by shutdown.
  const flush = () => tail;

  // --- what the routes report ------------------------------------------------------

  // The person, their device and their open session, which almost every event needs.
  async function contextFor(user, { tokenHash, client = {}, device } = {}) {
    const userId = await subjects.forUser(user);
    const deviceId = device?.fingerprint ? await subjects.forDevice(userId, device.fingerprint, { os: device.platform }) : null;
    const sessionId = await events.openSessionId(userId, sessionRef(tokenHash));
    return { userId, deviceId, sessionId, client };
  }

  const api = {
    flush,
    stats: () => ({ queued: depth, dropped }),
    coverage: coverageSummary(),

    // Sign-in. Opens the CrimGuard session that later events hang off.
    onLogin({ user, client = {}, tokenHash, timezone = null, device = null }) {
      return enqueue(async () => {
        const userId = await subjects.forUser(user);
        const deviceId = device?.fingerprint ? await subjects.forDevice(userId, device.fingerprint, { os: device.platform }) : null;
        const ref = sessionRef(tokenHash);
        const sessionId = await events.startSession({
          userId, deviceId, sessionRef: ref, ip: client.ip, userAgent: client.userAgent, countryCode: null,
        });
        await events.auth({
          userId, sessionId, deviceId, eventType: 'login_success', ip: client.ip,
          city: timezone, userAgent: client.userAgent,
        });
      });
    },

    onLoginFailure({ userId: redUserId, client = {} }) {
      return enqueue(async () => {
        const userId = redUserId == null ? null : await subjects.lookupUser(redUserId);
        // A failure against an email that isn't registered has no subject to attach to.
        if (userId == null) return;
        await events.auth({ userId, eventType: 'login_failure', ip: client.ip, userAgent: client.userAgent });
      });
    },

    onLogout({ user, tokenHash, client = {} }) {
      return enqueue(async () => {
        const userId = await subjects.forUser(user);
        await events.endSession({ sessionRef: sessionRef(tokenHash) });
        await events.auth({ userId, eventType: 'logout', ip: client.ip, userAgent: client.userAgent });
      });
    },

    // A session cookie presented after that session ended. Red itself can't say whose it was -
    // it deletes the row on sign-out - but the CrimGuard session is still on file with an
    // ended_at, and that names the account. A replayed token is the classic hijack signal.
    onStaleSession({ tokenHash, client = {} }) {
      const ref = sessionRef(tokenHash);
      if (!ref) return tail;
      return enqueue(async () => {
        const { rows } = await db.query(
          'SELECT id, user_id, device_id FROM user_sessions WHERE idp_session_id = ? AND ended_at IS NOT NULL LIMIT 1',
          [ref],
        );
        if (!rows.length) return;
        const { id, user_id: userId, device_id: deviceId } = rows[0];
        await events.auth({
          userId, sessionId: id, deviceId, eventType: 'session_token_reuse',
          ip: client.ip, userAgent: client.userAgent,
        });
      });
    },

    onPasswordChanged({ user, client = {}, tokenHash }) {
      return enqueue(async () => {
        const { userId, sessionId, deviceId } = await contextFor(user, { tokenHash, client });
        await events.auth({ userId, sessionId, deviceId, eventType: 'password_reset', ip: client.ip, userAgent: client.userAgent });
      });
    },

    // Something in Red was opened, changed or deleted.
    onAccess({ user, tokenHash, client, kind, id, name, action = 'read', bytes = null, searchQuery = null, batch = null, previousName = null }) {
      return enqueue(async () => {
        const { userId, sessionId, deviceId } = await contextFor(user, { tokenHash, client });
        const resourceId = await subjects.forResource(kind, id, name);
        await events.fileAccess({
          userId, sessionId, deviceId, resourceId, action, bytes,
          filePath: name || null, previousPath: previousName, searchQuery, filesInBatch: batch,
        });
      });
    },

    // Data leaving Red: the project export.
    onExport({ user, tokenHash, client, bytes, items, renamedFirst = false }) {
      return enqueue(async () => {
        const { userId, deviceId } = await contextFor(user, { tokenHash, client });
        const resourceId = await subjects.forResource('directory');
        await events.transfer({
          userId, deviceId, resourceId, channel: 'download', bytes, fileName: 'red-projects.json',
          destination: 'browser download', renamedBeforeExport: renamedFirst, sensitivity: 'internal',
        });
        await events.fileAccess({ userId, deviceId, resourceId, action: 'download', bytes, filesInBatch: items });
      });
    },

    // Text someone wrote inside Red, scanned for sensitive terms and secret shapes. Only the
    // counts and the category names are stored.
    onText({ user, tokenHash, client, text }) {
      const found = classifyText(text);
      if (!found.keywordHits && !found.hasSecret) return tail;
      return enqueue(async () => {
        const { userId } = await contextFor(user, { tokenHash, client });
        await events.communication({
          userId, channel: 'chat', eventType: found.hasSecret ? 'credential_shared' : 'message_sent',
          isExternal: false, sensitiveKeywordHits: found.keywordHits,
        });
      });
    },

    // An admin action, or a refusal that shows someone reaching past their role.
    onPrivilege({ actor, tokenHash, client, type, targetRedUserId = null, targetGroup = null, systemName = null, details = {} }) {
      return enqueue(async () => {
        const { userId } = await contextFor(actor, { tokenHash, client });
        const targetUserId = targetRedUserId == null ? null : await subjects.lookupUser(targetRedUserId);
        await events.privilege({ userId, targetUserId, eventType: type, targetGroup, systemName, details });
      });
    },

    // Bytes served to this person, for bandwidth_usage_spike.
    onBandwidth({ user, tokenHash, client, bytes }) {
      if (!bytes) return tail;
      return enqueue(async () => {
        const { userId, deviceId } = await contextFor(user, { tokenHash, client });
        await events.network({ userId, deviceId, ip: client?.ip, destinationDomain: 'red', bytesOut: bytes });
      });
    },

    // A batch from the browser collector: the pointer, typing, scroll, idle, clipboard,
    // print and screen-capture signals the server cannot see for itself.
    ingest({ user, tokenHash, client, body }) {
      const batch = parseBatch(body);
      enqueue(async () => {
        const userId = await subjects.forUser(user);
        const deviceId = batch.device.fingerprint
          ? await subjects.forDevice(userId, batch.device.fingerprint, { os: batch.device.platform })
          : null;
        const ref = sessionRef(tokenHash);
        const sessionId = await events.openSessionId(userId, ref);

        for (const sample of batch.samples) {
          await events.biometric({ ...sample, userId, sessionId, deviceId, openWindowCount: sample.openWindowCount ?? batch.windows });
        }
        for (const event of batch.events) {
          if (event.table === 'clipboard') {
            await events.clipboard({
              userId, deviceId, occurredAt: event.at, charCount: event.charCount,
              sourceApp: event.source, destinationApp: event.destination,
              detectedPatterns: event.patterns,
              classification: event.patterns.length ? 'restricted' : null,
            });
          } else {
            await events.endpoint({
              userId, deviceId, occurredAt: event.at, eventType: event.eventType, appName: 'red-web',
              isSanctionedApp: true,
              details: { pages: event.pages ?? undefined, sensitive: event.sensitiveOnScreen || undefined },
            });
          }
        }
        // Where this sign-in came from. The browser reports its time zone, which names a real
        // city; locate() turns that into coordinates so the impossible-travel check can work
        // in kilometres per hour rather than in hours of offset.
        if (batch.device.timezone && sessionId) {
          const place = locate({ timezone: batch.device.timezone });
          await db.query(
            `UPDATE user_sessions SET city = ?, country_code = ?, latitude = ?, longitude = ?
             WHERE id = ? AND city IS NULL`,
            [batch.device.timezone, place?.country ?? null, place?.latitude ?? null, place?.longitude ?? null, sessionId],
          );
          await db.query(
            `UPDATE auth_events SET city = ?, country_code = ?, latitude = ?, longitude = ?
             WHERE user_id = ? AND session_id = ? AND event_type = 'login_success' AND city IS NULL`,
            [batch.device.timezone, place?.country ?? null, place?.latitude ?? null, place?.longitude ?? null, userId, sessionId],
          );
        }
      });
      return { accepted: batch.samples.length + batch.events.length };
    },

    // Red is the system of record for people here, so a role change is also the HR event and
    // the role assignment the context ledger reads.
    onRoleChanged({ actor, tokenHash, client, target, from, to }) {
      return enqueue(async () => {
        const { userId } = await contextFor(actor, { tokenHash, client });
        const targetId = await subjects.forUser({ ...target, role: to });
        const at = new Date().toISOString();
        await events.privilege({ userId, targetUserId: targetId, eventType: 'permission_change', details: { from, to } });
        if (from !== to) {
          await events.privilege({ userId, targetUserId: targetId, eventType: 'sensitive_group_membership_change', targetGroup: ROLE_NAMES[to] });
          await events.privilege({ userId, targetUserId: targetId, eventType: 'new_system_access_granted', systemName: ROLE_NAMES[to] });
          await db.query('INSERT INTO hr_events (user_id, event_type, effective_date, recorded_at, details) VALUES (?, ?, ?, ?, ?)',
            [targetId, 'role_change', at.slice(0, 10), at, JSON.stringify({ from, to })]);
          await recordRoleAssignment(targetId, to, at.slice(0, 10));
        }
      });
    },

    onAccountCreated({ actor, tokenHash, client, created }) {
      return enqueue(async () => {
        const { userId } = await contextFor(actor, { tokenHash, client });
        const targetId = await subjects.forUser(created);
        await events.privilege({ userId, targetUserId: targetId, eventType: 'account_created', details: { role: created.role } });
        await recordRoleAssignment(targetId, created.role, new Date().toISOString().slice(0, 10));
      });
    },

    onAccountDeleted({ redUserId }) {
      return enqueue(async () => {
        const userId = await subjects.lookupUser(redUserId);
        subjects.forgetUser(redUserId);
        // The person's risk history is kept: deleting the account is itself the thing an
        // investigation would want to see. The link to the Red account is what goes.
        if (userId != null) await db.query('UPDATE users SET employment_status = ?, okta_user_id = NULL WHERE id = ?', ['terminated', userId]);
      });
    },

    // Someone reached for something their role doesn't cover.
    onViolation({ user, tokenHash, client, path }) {
      return enqueue(async () => {
        const { userId } = await contextFor(user, { tokenHash, client });
        await events.privilege({ userId, eventType: 'least_privilege_violation', systemName: path, details: { path } });
      });
    },

    // --- the daily job --------------------------------------------------------------

    // Aggregates and scores one day for everyone. Returns what it did, for the console.
    async runDay(date = today()) {
      await initialize();
      const org = await subjects.organization();
      const hours = await subjects.workingHours();
      const { rows: holidayRows } = await db.query('SELECT holiday_date FROM org_holidays WHERE org_id = ?', [org]);
      const holidays = holidayRows.map((row) => row.holiday_date);
      const { rows: people } = await db.query('SELECT id, okta_user_id FROM users WHERE org_id = ? ORDER BY id', [org]);

      let snapshots = 0;
      let scored = 0;
      let planted = 0;
      for (const person of people) {
        const { active, features } = await featuresFor(db, person.id, date, { holidays, hours });
        if (!active) continue;
        await writeSnapshot(db, { userId: person.id, date, features, layout });
        snapshots += 1;
        const result = await scorer.scoreUserDay(person.id, date);
        if (!result) continue;
        scored += 1;
        const redUserId = person.okta_user_id ? Number(person.okta_user_id.slice(4)) : null;
        if (redUserId && date === today() && await honeytokens.plantIfNeeded(redUserId, result.finalScore)) planted += 1;
        if (onScored && date === today()) await onScored({ crimUserId: person.id, redUserId, date, result });
      }
      return { date, people: people.length, snapshots, scored, planted };
    },

    // Aggregates and scores one person's day on the spot, so the live panel shows what has
    // happened in the last few seconds rather than what the last scheduled run saw. Results
    // are cached briefly: several tabs polling shouldn't each rebuild the same day.
    async refreshUser(user, { date = today(), maxAgeMs = 5000 } = {}) {
      await initialize();
      const key = `${user.id}:${date}`;
      const cached = refreshed.get(key);
      if (cached && Date.now() - cached.at < maxAgeMs) return cached.crimUserId;

      await flush();
      const crimUserId = await subjects.forUser(user);
      const hours = await subjects.workingHours();
      const org = await subjects.organization();
      const { rows } = await db.query('SELECT holiday_date FROM org_holidays WHERE org_id = ?', [org]);

      const { active, features } = await featuresFor(db, crimUserId, date, { holidays: rows.map((r) => r.holiday_date), hours });
      if (active) {
        await writeSnapshot(db, { userId: crimUserId, date, features, layout });
        const result = await scorer.scoreUserDay(crimUserId, date);
        // Crossing the threshold is what puts a decoy in front of them.
        if (result) await honeytokens.plantIfNeeded(user.id, result.finalScore);
        if (result && onScored && date === today()) await onScored({ crimUserId, redUserId: user.id, date, result });
      }
      refreshed.set(key, { at: Date.now(), crimUserId });
      return crimUserId;
    },

    // --- decoys ------------------------------------------------------------------------

    honeytokens: {
      plantScore: honeytokens.plantScore,
      // The decoy projects planted for one account, if any.
      listFor: (redUserId) => honeytokens.activeFor(redUserId).then((rows) => rows.map((row) => row.project)),
      // Someone changed or deleted one. Returns the report, or null when it wasn't a live decoy.
      trip: (args) => honeytokens.trip(args),
      plantIfNeeded: (redUserId, score) => honeytokens.plantIfNeeded(redUserId, score),
    },

    // --- reading it back --------------------------------------------------------------

    report: {
      async overview() {
        await initialize();
        const org = await subjects.organization();
        const { rows } = await db.query(
          `SELECT u.id, u.email, u.full_name, u.is_privileged, u.employment_type, u.termination_date, u.okta_user_id,
                  s.snapshot_date, r.final_score, r.risk_level, r.scenario, r.dashboard_payload
           FROM users u
           LEFT JOIN risk_feature_snapshot s ON s.id = (
             SELECT id FROM risk_feature_snapshot WHERE user_id = u.id ORDER BY snapshot_date DESC LIMIT 1)
           LEFT JOIN risk_scores r ON r.snapshot_id = s.id
           WHERE u.org_id = ?
           ORDER BY COALESCE(r.final_score, -1) DESC, u.full_name`,
          [org],
        );
        const { rows: alerts } = await db.query(
          `SELECT id, user_id, title, severity, scenario, status, first_seen_at, last_seen_at FROM alerts
           WHERE org_id = ? AND status IN ('open', 'investigating', 'escalated') ORDER BY last_seen_at DESC LIMIT 50`,
          [org],
        );

        return {
          coverage: coverageSummary(),
          people: rows.map((row) => ({
            id: row.id,
            redUserId: row.okta_user_id ? Number(row.okta_user_id.slice(4)) : null,
            name: row.full_name,
            email: row.email,
            role: row.is_privileged ? 'admin' : 'user',
            employmentType: row.employment_type,
            terminationDate: row.termination_date,
            lastSnapshot: row.snapshot_date,
            score: row.final_score == null ? null : Number(row.final_score),
            level: row.risk_level,
            scenario: row.scenario,
            dataQuality: row.dashboard_payload?.dataQuality ?? null,
          })),
          alerts,
        };
      },

      // Every one of the 100 variables for one person on one day, with where each came from.
      async person(crimUserId, { date = null, days = 30 } = {}) {
        await initialize();
        const { rows: found } = await db.query(
          `SELECT * FROM v_risk_feature_vector WHERE user_id = ?${date ? ' AND snapshot_date = ?' : ''}
           ORDER BY snapshot_date DESC LIMIT 1`,
          date ? [crimUserId, date] : [crimUserId],
        );
        const vector = found[0] || null;

        const [person, score, history, anomalies, past] = await Promise.all([
          db.query('SELECT id, email, full_name, is_privileged, employment_type, hire_date, termination_date FROM users WHERE id = ?', [crimUserId]),
          vector
            ? db.query('SELECT * FROM risk_scores WHERE snapshot_id = ? ORDER BY scored_at DESC LIMIT 1', [vector.snapshot_id])
            : { rows: [] },
          db.query(
            `SELECT s.snapshot_date, r.final_score, r.risk_level, r.scenario FROM risk_feature_snapshot s
             LEFT JOIN risk_scores r ON r.snapshot_id = s.id
             WHERE s.user_id = ? ORDER BY s.snapshot_date DESC LIMIT ?`, [crimUserId, days],
          ),
          vector ? db.query('SELECT * FROM anomalies WHERE snapshot_id = ? ORDER BY z_score DESC', [vector.snapshot_id]) : { rows: [] },
          // The 30 days before this one, to say what "usual" is for each variable.
          vector
            ? db.query(
              `SELECT * FROM v_risk_feature_vector WHERE user_id = ? AND snapshot_date < ?
               ORDER BY snapshot_date DESC LIMIT 30`, [crimUserId, vector.snapshot_date],
            )
            : { rows: [] },
        ]);

        const usual = baselinesFor(catalog, past.rows);

        return {
          person: person.rows[0] || null,
          date: vector?.snapshot_date ?? null,
          features: catalog.map((meta) => ({
            key: meta.key,
            category: meta.category,
            valueType: meta.valueType,
            signalRole: meta.signalRole,
            value: vector ? vector[meta.key] ?? null : null,
            ...usual[meta.key],
            collection: coverage[meta.key].collection,
            note: coverage[meta.key].note,
          })),
          score: score.rows[0] || null,
          anomalies: anomalies.rows,
          history: history.rows.slice().reverse(),
        };
      },

      // The same report, found by Red account rather than CrimGuard id. This is what someone
      // is shown about themselves.
      async forRedUser(redUserId, options) {
        await initialize();
        const crimUserId = await subjects.lookupUser(redUserId);
        if (crimUserId == null) return null;
        return api.report.person(crimUserId, options);
      },

      // The catalog itself, with how Red collects each entry.
      async catalogue() {
        await initialize();
        const { rows } = await db.query('SELECT feature_key, category, ordinal, value_type, unit, signal_role, description FROM feature_catalog ORDER BY category, ordinal');
        return rows.map((row) => ({
          key: row.feature_key,
          category: row.category,
          ordinal: row.ordinal,
          valueType: row.value_type,
          unit: row.unit,
          signalRole: row.signal_role,
          description: row.description,
          collection: coverage[row.feature_key].collection,
          note: coverage[row.feature_key].note,
        }));
      },
    },
  };

  // Keeps user_role_assignments in step with the role Red holds, so the context ledger can
  // explain access that follows a promotion.
  async function recordRoleAssignment(crimUserId, role, from) {
    const org = await subjects.organization();
    const name = ROLE_NAMES[role] || `Red ${role}`;
    let { rows } = await db.query('SELECT id FROM roles WHERE org_id = ? AND name = ?', [org, name]);
    if (!rows.length) {
      await db.query('INSERT INTO roles (org_id, name, is_privileged) VALUES (?, ?, ?)', [org, name, isPrivileged(role)]);
      ({ rows } = await db.query('SELECT id FROM roles WHERE org_id = ? AND name = ?', [org, name]));
    }
    const roleId = rows[0].id;
    await db.query('UPDATE user_role_assignments SET valid_to = ? WHERE user_id = ? AND valid_to IS NULL AND role_id <> ?', [from, crimUserId, roleId]);
    await db.query(
      `INSERT INTO user_role_assignments (user_id, role_id, valid_from, source) VALUES (?, ?, ?, 'red')
       ON CONFLICT DO NOTHING`, [crimUserId, roleId, from],
    );
  }

  return api;
}

// Used when the risk database is unavailable: every call is accepted and discarded, so the
// website behaves identically with or without it.
function createNoop() {
  const noop = () => Promise.resolve();
  const unavailable = async () => { throw new Error('The risk database is not connected.'); };
  return {
    enabled: false,
    flush: noop,
    stats: () => ({ queued: 0, dropped: 0 }),
    coverage: coverageSummary(),
    onLogin: noop, onLoginFailure: noop, onLogout: noop, onStaleSession: noop, onPasswordChanged: noop,
    onAccess: noop, onExport: noop, onText: noop, onPrivilege: noop, onBandwidth: noop,
    onRoleChanged: noop, onAccountCreated: noop, onAccountDeleted: noop, onViolation: noop,
    ingest: () => ({ accepted: 0 }),
    runDay: async () => ({ people: 0, snapshots: 0, scored: 0 }),
    refreshUser: async () => null,
    honeytokens: { plantScore: Infinity, listFor: async () => [], trip: async () => null, plantIfNeeded: async () => null },
    report: { overview: unavailable, person: unavailable, forRedUser: async () => null, catalogue: unavailable },
  };
}

module.exports = { createTelemetry, sessionRef };
