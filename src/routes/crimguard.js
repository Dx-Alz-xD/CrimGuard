'use strict';

// The CrimGuard dashboard's data: everyone in Red and everything Red holds on them, for admins and the
// CEO. It reads Red's own database, so it works with or without the risk database; when that is
// connected, each person's latest risk score is added.
//
// The page polls these endpoints every few seconds to stay live. Opening someone's record is a
// privileged act and is recorded, but at most once every ten minutes per viewer and person, so leaving
// the page open doesn't flood the activity log. Files above the viewer's clearance are counted, never
// named.

const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson } = require('../http/response');
const { isCeo, isPrivileged } = require('../security/access');
const { singleLine } = require('../validation');
const { isoDate } = require('./telemetry');

const RECORD_VIEW_EVERY_MS = 10 * 60 * 1000;
const RISK_CACHE_MS = 30 * 1000;
// Sessions are touched at most once a minute, so "online" allows a few minutes of quiet.
const ONLINE_MS = 5 * 60 * 1000;
const ACTIVITY_LIMIT = 60;

function registerCrimGuardRoutes(router, { stores, sessions, telemetry, crimguard, sessionPolicy, now = Date.now }) {
  const { people, files, audit, risk: riskState } = stores;
  const lastRecorded = new Map(); // `${viewerId}:${subject}` -> ms
  const riskCache = new Map(); // key -> { at, value }

  const cutoffs = (t) => ({ now: t, userSince: t - sessionPolicy.user.idleMs, adminSince: t - sessionPolicy.admin.idleMs });

  function shouldRecord(key, t) {
    const last = lastRecorded.get(key);
    if (last !== undefined && t - last < RECORD_VIEW_EVERY_MS) return false;
    if (lastRecorded.size > 5000) {
      for (const [oldKey, at] of lastRecorded) if (t - at >= RECORD_VIEW_EVERY_MS) lastRecorded.delete(oldKey);
    }
    lastRecorded.set(key, t);
    return true;
  }

  // Risk reports are the expensive part of a poll, and scores only change when the pipeline runs.
  async function cachedRisk(key, load) {
    if (!crimguard) return null;
    const t = now();
    const hit = riskCache.get(key);
    if (hit && t - hit.at < RISK_CACHE_MS) return hit.value;
    const value = await load().catch(() => null);
    riskCache.set(key, { at: t, value });
    return value;
  }

  const riskOverview = () => cachedRisk('overview', async () => {
    const report = await telemetry.report.overview();
    const redIdByCrimId = new Map(report.people.map((person) => [person.id, person.redUserId]));
    const byUser = new Map();
    for (const person of report.people) {
      if (person.redUserId == null) continue;
      byUser.set(person.redUserId, { score: person.score, level: person.level, scenario: person.scenario, date: person.lastSnapshot, alerts: 0 });
    }
    for (const alert of report.alerts) {
      const entry = byUser.get(redIdByCrimId.get(alert.user_id));
      if (entry) entry.alerts += 1;
    }
    return { byUser, alerts: report.alerts.length };
  });

  const riskFor = (id) => cachedRisk(`person:${id}`, async () => {
    const report = await telemetry.report.forRedUser(id);
    if (!report) return null;
    const { score } = report;
    return {
      date: report.date,
      score: score ? Number(score.final_score) : null,
      level: score?.risk_level ?? null,
      scenario: score?.scenario ?? null,
      contextMultiplier: score ? Number(score.context_multiplier) : null,
      hrAmplifier: score ? Number(score.hr_amplifier) : null,
      contributions: (score?.dashboard_payload?.contributions ?? []).slice(0, 8),
      history: report.history.map((day) => ({
        date: day.snapshot_date,
        score: day.final_score == null ? null : Number(day.final_score),
        level: day.risk_level,
      })),
    };
  });

  router.get('/api/crimguard/overview', async ({ req, res, client }) => {
    const viewer = sessions.requireAdmin(req);
    const t = now();
    const risk = await riskOverview();
    const list = people.overview(cutoffs(t)).map((row) => ({
      ...row,
      online: row.last_seen_at != null && t - row.last_seen_at < ONLINE_MS,
      risk: risk?.byUser.get(row.id) ?? null,
    }));

    if (shouldRecord(`${viewer.id}:directory`, t)) {
      telemetry.onAccess({
        user: viewer, tokenHash: req.sessionTokenHash, client, kind: 'directory', name: 'People directory',
        action: 'read', batch: list.length,
      });
    }

    const sum = (key) => list.reduce((total, row) => total + row[key], 0);
    sendJson(res, 200, {
      generatedAt: new Date(t).toISOString(),
      riskConnected: Boolean(crimguard),
      totals: {
        people: list.length,
        online: list.filter((row) => row.online).length,
        projects: sum('project_count'),
        files: sum('file_count'),
        bytes: sum('file_bytes'),
        sessions: sum('session_count'),
        alerts: risk?.alerts ?? null,
      },
      people: list,
    });
  });

  router.get('/api/crimguard/people/:id', async ({ req, res, params: { id }, client }) => {
    const viewer = sessions.requireAdmin(req);
    const person = people.person(id);
    if (!person) throw new HttpError(404, 'There is no account with that id.');
    const t = now();

    // Recorded before the activity is read, so the view itself shows up in it.
    if (viewer.id !== id && shouldRecord(`${viewer.id}:${id}`, t)) {
      audit.record('crimguard.person_viewed', { actor: viewer, target: person, ...client });
      telemetry.onAccess({
        user: viewer, tokenHash: req.sessionTokenHash, client, kind: 'account', id, name: person.email, action: 'read',
      });
    }

    const owned = files.forOwner(id, viewer.id);
    const projects = people.projects(id).map((project) => {
      const inProject = owned.filter((file) => file.project_id === project.id);
      return {
        ...project,
        files: inProject.filter((file) => file.visible).map(({ visible, project_id: projectId, ...file }) => file),
        hidden_files: inProject.filter((file) => !file.visible).length,
      };
    });
    const liveSessions = people.sessions(id, cutoffs(t));
    const lastSeen = liveSessions[0]?.last_seen_at ?? null;

    sendJson(res, 200, {
      generatedAt: new Date(t).toISOString(),
      riskConnected: Boolean(crimguard),
      person: {
        ...person,
        must_change_password: person.must_change_password === 1,
        last_seen_at: lastSeen,
        online: lastSeen != null && t - lastSeen < ONLINE_MS,
      },
      totals: {
        projects: projects.length,
        files: owned.length,
        hiddenFiles: owned.filter((file) => !file.visible).length,
        bytes: owned.reduce((total, file) => total + file.size, 0),
      },
      projects,
      shared: files.sharedWith(id, viewer.id),
      sessions: liveSessions,
      activity: people.activity(id, ACTIVITY_LIMIT),
      risk: await riskFor(id),
      limit: riskState.limitFor(id),
      // Switching limiting off for an admin, or for yourself, is the CEO's call alone: an admin
      // who could waive their own limit would make the whole thing optional.
      canChangeLimit: isCeo(viewer.role) || (viewer.id !== id && !isPrivileged(person.role)),
    });
  });

  // The 100 variables as they stand for one person, for the test dialog to start from. Not part
  // of the record itself: it would ride along on every poll for something opened now and then.
  router.get('/api/crimguard/people/:id/variables', async ({ req, res, params: { id } }) => {
    sessions.requireAdmin(req);
    if (!crimguard) throw new HttpError(503, 'The risk database is not connected.');
    if (!people.person(id)) throw new HttpError(404, 'There is no account with that id.');

    const report = await telemetry.report.forRedUser(id);
    sendJson(res, 200, {
      date: report ? report.date : null,
      variables: report ? report.features : [],
    });
  });

  // --- test overrides ---------------------------------------------------------------------
  //
  // TEMPORARY, and admin-only. Sets a person's variables for a day, or forces their score, so
  // the thresholds that hang off it - limiting at 75 and 85, a decoy at 40 - can be exercised
  // on demand. Both write ordinary rows in the ordinary tables; nothing here is a special case
  // further down. It lives under /api/crimguard because a :id here is a Red account, as it is
  // everywhere else on this dashboard.

  // The catalog decides what a value may be, so a variable can't be set to something the
  // snapshot tables would reject.
  function featureValue(meta, raw) {
    if (raw === null || raw === '') return null;
    switch (meta.value_type) {
      case 'flag':
        if (typeof raw === 'boolean') return raw;
        if (raw === 'true' || raw === 'false') return raw === 'true';
        throw new HttpError(400, `${meta.feature_key} is a flag: true or false.`);
      case 'count': case 'seconds': case 'months': {
        const n = Number(raw);
        if (!Number.isInteger(n) || n < 0) throw new HttpError(400, `${meta.feature_key} is a whole number, 0 or more.`);
        return n;
      }
      case 'date':
        return isoDate(raw, meta.feature_key);
      case 'category':
        if (typeof raw !== 'string' || raw.length > 40) throw new HttpError(400, `${meta.feature_key} must be a short word.`);
        return raw;
      default: {
        const n = Number(raw);
        if (!Number.isFinite(n)) throw new HttpError(400, `${meta.feature_key} must be a number.`);
        return n;
      }
    }
  }

  router.put('/api/crimguard/people/:id/override', async ({ req, res, params: { id }, client }) => {
    const admin = sessions.requireAdmin(req);
    if (!crimguard) throw new HttpError(503, 'The risk database is not connected.');
    const body = await readJson(req);

    // The id here is a Red account, the same as everywhere else in the admin console.
    const person = people.person(id);
    if (!person) throw new HttpError(404, 'There is no account with that id.');

    const on = body.date ? isoDate(body.date, 'date') : new Date().toISOString().slice(0, 10);

    let score = null;
    if (body.score !== undefined && body.score !== null && body.score !== '') {
      score = Number(body.score);
      if (!Number.isFinite(score) || score < 0 || score > 100) throw new HttpError(400, 'Score must be between 0 and 100.');
    }

    const features = {};
    if (body.features && typeof body.features === 'object') {
      const { rows: catalog } = await crimguard.query('SELECT feature_key, value_type FROM feature_catalog');
      const byKey = new Map(catalog.map((row) => [row.feature_key, row]));
      for (const [key, raw] of Object.entries(body.features)) {
        const meta = byKey.get(key);
        if (!meta) throw new HttpError(400, `There is no variable called ${key}.`);
        features[key] = featureValue(meta, raw);
      }
    }

    const result = await telemetry.override(person, { date: on, features, score, level: body.level ?? null });
    audit.record('risk.override', {
      actor: admin, target: person, ...client,
      details: { date: on, forced: result.forced, score: result.score, variables: Object.keys(features).length },
    });
    sendJson(res, 200, { ...result, limit: riskState.limitFor(id) });
  });

  // Turn risk limiting off for one person, or back on. The rule itself is not configurable here
  // - only whether it applies to this account.
  router.patch('/api/crimguard/people/:id/limit', async ({ req, res, params: { id }, client }) => {
    const viewer = sessions.requireAdmin(req);
    const person = people.person(id);
    if (!person) throw new HttpError(404, 'There is no account with that id.');

    const body = await readJson(req);
    if (typeof body.enabled !== 'boolean') throw new HttpError(400, 'Say whether limiting should be on or off.');

    if (!isCeo(viewer.role)) {
      if (viewer.id === id) throw new HttpError(403, "You can't change your own limit. Ask the CEO.");
      if (isPrivileged(person.role)) throw new HttpError(403, "Only the CEO can change an admin's limit.");
    }

    const reason = singleLine(body.reason || '').slice(0, 200);
    if (body.enabled) {
      riskState.unexempt(id);
    } else {
      riskState.exempt(id, { by: viewer, reason });
    }
    audit.record(body.enabled ? 'risk.limit_enabled' : 'risk.limit_disabled', {
      actor: viewer, target: person, ...client, details: { reason: reason || undefined },
    });
    telemetry.onPrivilege({
      actor: viewer, tokenHash: req.sessionTokenHash, client, type: 'permission_change',
      targetRedUserId: id, systemName: 'risk-limit', details: { enabled: body.enabled },
    });

    sendJson(res, 200, { limit: riskState.limitFor(id) });
  });
}

module.exports = { registerCrimGuardRoutes };
