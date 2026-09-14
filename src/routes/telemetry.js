'use strict';

// The collector's endpoint, and the admin-only risk console behind it.
//
// /api/telemetry is the one route the browser collector posts to. Everything under
// /api/admin/risk reads what the pipeline produced, or records the HR context that Red has no
// other system to keep - employment type, a leaving date, a review or a period of leave -
// which is what the engine's amplifier runs on.

const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson } = require('../http/response');

const EMPLOYMENT_TYPES = ['full_time', 'contractor', 'temp'];
const LEAVE_TYPES = ['pto', 'sick', 'parental', 'sabbatical', 'garden_leave', 'unpaid', 'other'];
// The HR events an admin can record by hand. Role changes are written by Red itself.
const HR_EVENT_TYPES = ['performance_review', 'disciplinary_action', 'manager_change', 'compensation_change',
  'resignation_notice', 'termination_scheduled'];

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

function date(value, field, { required = false } = {}) {
  if (value === null || value === undefined || value === '') {
    if (required) throw new HttpError(400, `${field} is required.`);
    return null;
  }
  if (typeof value !== 'string' || !ISO_DATE.test(value) || Number.isNaN(Date.parse(`${value}T00:00:00Z`))) {
    throw new HttpError(400, `${field} must be a date, as YYYY-MM-DD.`);
  }
  return value;
}

function oneOf(value, allowed, field) {
  if (!allowed.includes(value)) throw new HttpError(400, `${field} must be one of: ${allowed.join(', ')}.`);
  return value;
}

function positive(value, field, max) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > max) throw new HttpError(400, `${field} must be between 0 and ${max}.`);
  return n;
}

function registerTelemetryRoutes(router, { sessions, telemetry, crimguard }) {
  // The collector. Anyone signed in posts their own behaviour here, and only their own: the
  // account comes from the session, never from the body.
  router.post('/api/telemetry', async ({ req, res, client }) => {
    const user = sessions.requireUser(req);
    const { accepted } = telemetry.ingest({
      user, tokenHash: req.sessionTokenHash, client, body: await readJson(req),
    });
    sendJson(res, 202, { accepted });
  });

  // Someone's own risk assessment, recomputed on the spot. Everyone can see this about
  // themselves - it is their own behaviour, scored - and nobody can see it about anyone else:
  // the account comes from the session, so there is nothing to point at another person.
  router.get('/api/me/risk', async ({ req, res }) => {
    const user = sessions.requireUser(req);
    if (!crimguard) throw new HttpError(503, 'The risk database is not connected.');

    await telemetry.refreshUser(user);
    const report = await telemetry.report.forRedUser(user.id);
    if (!report) {
      // Nothing recorded yet: a brand-new account on its first page view.
      sendJson(res, 200, { date: null, score: null, features: [], history: [], coverage: telemetry.coverage });
      return;
    }
    sendJson(res, 200, {
      date: report.date,
      scoredAt: report.score?.scored_at ?? null,
      score: report.score && {
        finalScore: Number(report.score.final_score),
        riskLevel: report.score.risk_level,
        scenario: report.score.scenario,
        contextMultiplier: Number(report.score.context_multiplier),
        hrAmplifier: Number(report.score.hr_amplifier),
        contributions: report.score.dashboard_payload?.contributions ?? [],
        categories: report.score.dashboard_payload?.categories ?? [],
        dataQuality: report.score.dashboard_payload?.dataQuality ?? null,
      },
      features: report.features,
      history: report.history,
      coverage: telemetry.coverage,
    });
  });

  // --- the risk console -------------------------------------------------------------

  const requireRisk = (req) => {
    const admin = sessions.requireAdmin(req);
    if (!crimguard) throw new HttpError(503, 'The risk database is not connected.');
    return admin;
  };

  router.get('/api/admin/risk/overview', async ({ req, res }) => {
    requireRisk(req);
    sendJson(res, 200, await telemetry.report.overview());
  });

  router.get('/api/admin/risk/catalog', async ({ req, res }) => {
    requireRisk(req);
    sendJson(res, 200, { features: await telemetry.report.catalogue(), coverage: telemetry.coverage });
  });

  router.get('/api/admin/risk/people/:id', async ({ req, res, params: { id }, url }) => {
    requireRisk(req);
    const on = url.searchParams.get('date');
    const report = await telemetry.report.person(id, { date: on ? date(on, 'date') : null });
    if (!report.person) throw new HttpError(404, 'No risk record for that person.');
    sendJson(res, 200, report);
  });

  // Recompute and rescore a day on demand, rather than waiting for the next run.
  router.post('/api/admin/risk/run', async ({ req, res }) => {
    requireRisk(req);
    const body = await readJson(req);
    const on = body.date ? date(body.date, 'date') : new Date().toISOString().slice(0, 10);
    await telemetry.flush();
    sendJson(res, 200, await telemetry.runDay(on));
  });

  // --- HR context ---------------------------------------------------------------------

  // Employment details. These feed tenure_months, employment_type and
  // termination_date_on_file, and the engine's HR amplifier.
  router.patch('/api/admin/risk/people/:id', async ({ req, res, params: { id }, client }) => {
    const admin = requireRisk(req);
    const body = await readJson(req);
    const { rows } = await crimguard.query('SELECT id, hire_date FROM users WHERE id = ?', [id]);
    if (!rows.length) throw new HttpError(404, 'No risk record for that person.');

    const employmentType = Object.hasOwn(body, 'employmentType')
      ? oneOf(body.employmentType, EMPLOYMENT_TYPES, 'Employment type') : undefined;
    const hireDate = Object.hasOwn(body, 'hireDate') ? date(body.hireDate, 'Hire date') : undefined;
    const terminationDate = Object.hasOwn(body, 'terminationDate') ? date(body.terminationDate, 'Leaving date') : undefined;

    const effectiveHire = hireDate === undefined ? rows[0].hire_date : hireDate;
    if (terminationDate && effectiveHire && terminationDate < effectiveHire) {
      throw new HttpError(400, 'The leaving date cannot be before the hire date.');
    }

    const sets = [];
    const values = [];
    if (employmentType !== undefined) { sets.push('employment_type = ?'); values.push(employmentType); }
    if (hireDate !== undefined) { sets.push('hire_date = ?'); values.push(hireDate); }
    if (terminationDate !== undefined) {
      sets.push('employment_status = ?');
      values.push(terminationDate ? 'notice_period' : 'active');
      sets.push('termination_date = ?');
      values.push(terminationDate);
    }
    if (!sets.length) throw new HttpError(400, 'Nothing to change.');

    await crimguard.query(`UPDATE users SET ${sets.join(', ')}, updated_at = ? WHERE id = ?`,
      [...values, new Date().toISOString(), id]);

    // A leaving date is itself the HR event the amplifier ramps on.
    if (terminationDate) {
      await crimguard.query(
        `INSERT INTO hr_events (user_id, event_type, effective_date, recorded_at, source_system) VALUES (?, ?, ?, ?, 'red')`,
        [id, 'termination_scheduled', terminationDate, new Date().toISOString()],
      );
    }
    telemetry.onPrivilege({
      actor: admin, tokenHash: req.sessionTokenHash, client, type: 'permission_change',
      systemName: 'hr-context', details: { subject: Number(id) },
    });
    sendJson(res, 200, { ok: true });
  });

  router.post('/api/admin/risk/people/:id/hr-events', async ({ req, res, params: { id } }) => {
    requireRisk(req);
    const body = await readJson(req);
    const { rows } = await crimguard.query('SELECT id FROM users WHERE id = ?', [id]);
    if (!rows.length) throw new HttpError(404, 'No risk record for that person.');

    const type = oneOf(body.type, HR_EVENT_TYPES, 'Event type');
    const effectiveDate = date(body.effectiveDate, 'Effective date', { required: true });
    // A review only counts towards risk when it was a bad one; the others are stressors either way.
    const isNegative = type === 'performance_review' ? body.isNegative === true : true;

    await crimguard.query(
      `INSERT INTO hr_events (user_id, event_type, effective_date, recorded_at, is_negative, source_system) VALUES (?, ?, ?, ?, ?, 'red')`,
      [id, type, effectiveDate, new Date().toISOString(), isNegative],
    );
    sendJson(res, 201, { ok: true });
  });

  router.post('/api/admin/risk/people/:id/leave', async ({ req, res, params: { id } }) => {
    requireRisk(req);
    const body = await readJson(req);
    const { rows } = await crimguard.query('SELECT id FROM users WHERE id = ?', [id]);
    if (!rows.length) throw new HttpError(404, 'No risk record for that person.');

    const leaveType = oneOf(body.leaveType, LEAVE_TYPES, 'Leave type');
    const startsOn = date(body.startsOn, 'Start date', { required: true });
    const endsOn = date(body.endsOn, 'End date', { required: true });
    if (endsOn < startsOn) throw new HttpError(400, 'Leave cannot end before it starts.');

    const daysRequested = body.daysRequested == null ? null : positive(body.daysRequested, 'Days requested', 400);
    const balanceBefore = body.balanceBefore == null ? null : positive(body.balanceBefore, 'Balance before', 400);

    await crimguard.query(
      `INSERT INTO leave_periods (user_id, leave_type, starts_on, ends_on, days_requested, balance_before, requested_at, approved)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, leaveType, startsOn, endsOn, daysRequested, balanceBefore, new Date().toISOString(), true],
    );
    sendJson(res, 201, { ok: true });
  });

  router.delete('/api/admin/risk/people/:id/leave', async ({ req, res, params: { id }, url }) => {
    requireRisk(req);
    const leaveId = Number(url.searchParams.get('leave'));
    if (!Number.isInteger(leaveId) || leaveId <= 0) throw new HttpError(400, 'Which leave period?');
    const { rowCount } = await crimguard.query('DELETE FROM leave_periods WHERE id = ? AND user_id = ?', [leaveId, id]);
    if (!rowCount) throw new HttpError(404, 'Leave period not found.');
    sendJson(res, 200, { ok: true });
  });

  // The HR timeline as it stands, for the dialog that edits it.
  router.get('/api/admin/risk/people/:id/hr', async ({ req, res, params: { id } }) => {
    requireRisk(req);
    const [person, events, leave] = await Promise.all([
      crimguard.query('SELECT id, full_name, email, employment_type, hire_date, termination_date, employment_status FROM users WHERE id = ?', [id]),
      crimguard.query('SELECT id, event_type, effective_date, is_negative, recorded_at FROM hr_events WHERE user_id = ? ORDER BY effective_date DESC LIMIT 50', [id]),
      crimguard.query('SELECT id, leave_type, starts_on, ends_on, days_requested, balance_before FROM leave_periods WHERE user_id = ? ORDER BY starts_on DESC LIMIT 50', [id]),
    ]);
    if (!person.rows.length) throw new HttpError(404, 'No risk record for that person.');
    sendJson(res, 200, { person: person.rows[0], events: events.rows, leave: leave.rows });
  });
}

module.exports = { registerTelemetryRoutes, isoDate: date, EMPLOYMENT_TYPES, LEAVE_TYPES, HR_EVENT_TYPES };
