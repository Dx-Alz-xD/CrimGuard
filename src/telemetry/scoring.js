'use strict';

// Runs crimguard/risk over the stored snapshots and writes the result back: one risk_scores
// row per person per day, one anomalies row per feature the detectors flagged, and an alert
// when the day comes out high or critical.
//
// This is the job the risk README lists as missing - "no job reads the database and writes
// risk_scores" - now reading whatever the website has collected.

const { createRiskEngine, normalizeCatalog, toRiskScoreRow, MODEL_VERSION } = require('../../crimguard/risk');
const { readVectors, readPeerValues } = require('./snapshots');

const SCORING_HISTORY_DAYS = 180;
const CARRY_DAYS = 14;
const ALERT_LEVELS = new Set(['high', 'critical']);

// Which detector produced a hit maps onto the schema's detection_method enum.
const DETECTION_METHOD = { self: 'z_score', peer: 'z_score', drift: 'drift_trend', flag: 'rule' };

const addDays = (date, days) => new Date(Date.parse(`${date}T00:00:00Z`) + days * 86400000).toISOString().slice(0, 10);

async function loadCatalog(db) {
  const { rows } = await db.query('SELECT * FROM feature_catalog');
  if (!rows.length) throw new Error('The CrimGuard feature catalog is empty.');
  return normalizeCatalog(rows);
}

// Per-org weight and threshold overrides, in the shape createRiskEngine expects.
async function loadOrgSettings(db, orgId) {
  const { rows } = await db.query('SELECT feature_key, is_enabled, weight, z_threshold FROM org_feature_settings WHERE org_id = ?', [orgId]);
  return Object.fromEntries(rows.map((row) => [row.feature_key, {
    isEnabled: row.is_enabled !== false,
    weight: row.weight == null ? undefined : Number(row.weight),
    zThreshold: row.z_threshold == null ? undefined : Number(row.z_threshold),
  }]));
}

// The subject as the engine wants it: employment details plus the dated HR timeline that
// drives the amplifier.
async function loadSubject(db, userId) {
  const [person, events, leave] = await Promise.all([
    db.query('SELECT employment_type, hire_date, termination_date, is_privileged, org_id FROM users WHERE id = ?', [userId]),
    db.query('SELECT event_type, effective_date, recorded_at, is_negative FROM hr_events WHERE user_id = ? ORDER BY effective_date DESC LIMIT 100', [userId]),
    db.query('SELECT requested_at, days_requested, balance_before, starts_on FROM leave_periods WHERE user_id = ? ORDER BY starts_on DESC LIMIT 50', [userId]),
  ]);
  const row = person.rows[0] || {};
  return {
    orgId: row.org_id,
    isPrivileged: row.is_privileged === true,
    employmentType: row.employment_type || 'full_time',
    hireDate: row.hire_date || null,
    terminationDate: row.termination_date || null,
    hr: {
      terminationDate: row.termination_date || null,
      events: events.rows.map((event) => ({
        type: event.event_type,
        isNegative: event.is_negative === true,
        effectiveDate: event.effective_date,
        recordedAt: event.recorded_at,
      })),
      leave: leave.rows.map((period) => ({
        requestedAt: period.requested_at || period.starts_on,
        daysRequested: period.days_requested == null ? null : Number(period.days_requested),
        balanceBefore: period.balance_before == null ? null : Number(period.balance_before),
      })),
    },
  };
}

// The ledger entries that can explain a spike: tickets assigned, projects joined, role changes.
async function loadContext(db, userId) {
  const [tickets, projects, roles] = await Promise.all([
    db.query(`SELECT t.external_key, t.status, t.opened_at, t.due_at, t.closed_at, t.expected_daily_file_volume,
                     t.expected_access_multiplier, t.approved_by, ta.assigned_at, ta.unassigned_at
              FROM ticket_assignments ta JOIN tickets t ON t.id = ta.ticket_id
              WHERE ta.user_id = ? ORDER BY ta.assigned_at DESC LIMIT 50`, [userId]),
    db.query(`SELECT p.name, p.starts_on, p.ends_on, pm.joined_on, pm.left_on
              FROM project_members pm JOIN projects p ON p.id = pm.project_id
              WHERE pm.user_id = ? ORDER BY pm.joined_on DESC LIMIT 50`, [userId]),
    db.query(`SELECT r.name, ura.valid_from FROM user_role_assignments ura JOIN roles r ON r.id = ura.role_id
              WHERE ura.user_id = ? ORDER BY ura.valid_from DESC LIMIT 20`, [userId]),
  ]);

  return {
    tickets: tickets.rows.map((row) => ({
      key: row.external_key,
      approved: row.approved_by != null,
      status: row.status,
      openedAt: row.opened_at,
      assignedAt: row.assigned_at,
      dueAt: row.due_at,
      closedAt: row.closed_at,
      unassignedAt: row.unassigned_at,
      expectedDailyFileVolume: row.expected_daily_file_volume == null ? null : Number(row.expected_daily_file_volume),
      expectedAccessMultiplier: row.expected_access_multiplier == null ? null : Number(row.expected_access_multiplier),
    })),
    projects: projects.rows.map((row) => ({
      name: row.name, startsOn: row.starts_on, endsOn: row.ends_on, joinedOn: row.joined_on, leftOn: row.left_on,
    })),
    roleChanges: roles.rows.map((row) => ({ role: row.name, validFrom: row.valid_from })),
  };
}

// The highest criticality_weight this person touched that day, which is the engine's impact term.
async function assetWeights(db, userId, from, to) {
  const { rows } = await db.query(
    `SELECT substr(f.occurred_at, 1, 10) AS day, MAX(r.criticality_weight) AS weight
     FROM file_access_events f JOIN resources r ON r.id = f.resource_id
     WHERE f.user_id = ? AND f.occurred_at >= ? AND f.occurred_at < ?
     GROUP BY substr(f.occurred_at, 1, 10)`,
    [userId, `${from}T00:00:00.000Z`, `${addDays(to, 1)}T00:00:00.000Z`],
  );
  return new Map(rows.map((row) => [row.day, Number(row.weight)]));
}

async function honeytokenTripsByDay(db, userId, from, to) {
  const { rows } = await db.query(
    `SELECT substr(occurred_at, 1, 10) AS day, COUNT(*) AS trips FROM honeytoken_triggers
     WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ? GROUP BY substr(occurred_at, 1, 10)`,
    [userId, `${from}T00:00:00.000Z`, `${addDays(to, 1)}T00:00:00.000Z`],
  );
  return new Map(rows.map((row) => [row.day, Number(row.trips)]));
}

function createScorer(db, { catalog, orgSettings = {} }) {
  const engine = createRiskEngine({ catalog, orgSettings });
  const featureKeys = catalog.map((meta) => meta.key);

  // Turns a stored feature vector into the day the engine scores.
  const toDay = (row, { weights, trips, context }) => ({
    date: row.snapshot_date,
    features: Object.fromEntries(featureKeys.map((key) => [key, row[key] ?? null])),
    assetWeight: weights.get(row.snapshot_date) ?? undefined,
    honeytokenTrips: trips.get(row.snapshot_date) ?? 0,
    context,
  });

  // Scores one person on one day, using their own recent history as the baseline.
  async function scoreUserDay(userId, date) {
    const from = addDays(date, -SCORING_HISTORY_DAYS);
    const vectors = await readVectors(db, userId, { from, to: date });
    const today = vectors.find((row) => row.snapshot_date === date);
    if (!today) return null;

    const [subject, context, weights, trips] = await Promise.all([
      loadSubject(db, userId), loadContext(db, userId),
      assetWeights(db, userId, from, date), honeytokenTripsByDay(db, userId, from, date),
    ]);

    const peers = subject.orgId
      ? await readPeerValues(db, {
        orgId: subject.orgId, isPrivileged: subject.isPrivileged, excludeUserId: userId,
        from, to: date, keys: featureKeys,
      })
      : {};

    // What the engine carries forward from recent days, read back out of the stored payloads.
    const { rows: recent } = await db.query(
      `SELECT s.snapshot_date, r.dashboard_payload FROM risk_scores r
       JOIN risk_feature_snapshot s ON s.id = r.snapshot_id
       WHERE r.user_id = ? AND s.snapshot_date >= ? AND s.snapshot_date < ? AND r.model_version = ?
       ORDER BY s.snapshot_date`,
      [userId, addDays(date, -CARRY_DAYS), date, MODEL_VERSION],
    );
    const previous = recent
      .map((row) => ({ date: row.snapshot_date, carry: row.dashboard_payload?.carry || [] }))
      .filter((entry) => entry.carry.length);

    const history = vectors.filter((row) => row.snapshot_date < date).map((row) => toDay(row, { weights, trips, context }));
    const result = engine.scoreDay({
      subject, day: toDay(today, { weights, trips, context }), history, peers, previous,
    });

    await persist(db, { result, snapshotId: today.snapshot_id, userId, orgId: subject.orgId });
    return result;
  }

  return { engine, scoreUserDay, featureKeys };
}

// --- writing the result back -------------------------------------------------------

async function persist(db, { result, snapshotId, userId, orgId }) {
  const row = toRiskScoreRow(result, { snapshotId, userId });

  await db.query('DELETE FROM risk_scores WHERE snapshot_id = ? AND model_version = ?', [snapshotId, row.model_version]);
  await db.query(
    `INSERT INTO risk_scores
       (snapshot_id, user_id, model_version, statistical_anomaly_score, isolation_forest_score, drift_score,
        asset_criticality_weight, context_multiplier, hr_amplifier, honeytoken_override, final_score, risk_level,
        scenario, feature_contributions, dashboard_payload)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [row.snapshot_id, row.user_id, row.model_version, row.statistical_anomaly_score, row.isolation_forest_score,
      row.drift_score, row.asset_criticality_weight, row.context_multiplier, row.hr_amplifier, row.honeytoken_override,
      row.final_score, row.risk_level, row.scenario, row.feature_contributions, row.dashboard_payload],
  );

  // One anomalies row per feature a detector actually flagged, so the evidence behind a score
  // is queryable rather than only readable inside the JSON payload.
  await db.query('DELETE FROM anomalies WHERE snapshot_id = ?', [snapshotId]);
  for (const item of result.contributions) {
    if (!item.detector || item.carriedFrom) continue;
    await db.query(
      `INSERT INTO anomalies
         (snapshot_id, user_id, feature_key, detection_method, observed_value, baseline_mean, z_score, z_threshold,
          drift_pct_vs_anchor, model_version)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [snapshotId, userId, item.feature, DETECTION_METHOD[item.detector] || 'rule',
        typeof item.observed === 'number' ? item.observed : null,
        item.baselineMedian ?? null,
        item.z?.[item.detector] ?? item.z?.self ?? null,
        item.zThreshold ?? null,
        item.driftPct ?? null,
        result.modelVersion],
    );
  }

  if (ALERT_LEVELS.has(result.riskLevel) && orgId) await raiseAlert(db, { result, userId, orgId });
  return row;
}

// One open alert per person per scenario: a run of risky days updates the existing alert
// rather than filling the queue with a row a day.
async function raiseAlert(db, { result, userId, orgId }) {
  const at = `${result.date}T23:59:59.999Z`;
  const title = `${result.riskLevel === 'critical' ? 'Critical' : 'High'} insider risk: ${result.scenario.replace(/_/g, ' ')}`;
  const summary = result.contributions.slice(0, 3)
    .map((item) => `${item.feature} (${item.points} pts)`).join(', ') || 'No single dominant signal.';

  const { rows } = await db.query(
    `SELECT id, severity FROM alerts WHERE user_id = ? AND scenario = ? AND status IN ('open', 'investigating', 'escalated')
     ORDER BY id DESC LIMIT 1`,
    [userId, result.scenario],
  );

  if (rows.length) {
    const severity = result.riskLevel === 'critical' ? 'critical' : rows[0].severity;
    await db.query('UPDATE alerts SET last_seen_at = ?, severity = ?, summary = ?, updated_at = ? WHERE id = ?',
      [at, severity, summary, new Date().toISOString(), rows[0].id]);
    return rows[0].id;
  }

  await db.query(
    `INSERT INTO alerts (org_id, user_id, title, summary, severity, scenario, first_seen_at, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [orgId, userId, title, summary, result.riskLevel, result.scenario, at, at],
  );
  return null;
}

module.exports = { createScorer, loadCatalog, loadOrgSettings, loadSubject, loadContext, SCORING_HISTORY_DAYS };
