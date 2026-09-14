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
const { sendJson } = require('../http/response');

const RECORD_VIEW_EVERY_MS = 10 * 60 * 1000;
const RISK_CACHE_MS = 30 * 1000;
// Sessions are touched at most once a minute, so "online" allows a few minutes of quiet.
const ONLINE_MS = 5 * 60 * 1000;
const ACTIVITY_LIMIT = 60;

function registerCrimGuardRoutes(router, { stores, sessions, telemetry, crimguard, sessionPolicy, now = Date.now }) {
  const { people, files, audit } = stores;
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
    });
  });
}

module.exports = { registerCrimGuardRoutes };
