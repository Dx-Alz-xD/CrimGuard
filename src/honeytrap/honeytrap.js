'use strict';

// Dynamic honeytrapping. When someone's risk score crosses a threshold, a decoy chosen for them
// (lures.js) and carrying freshly minted fake credentials (canaries.js) appears among the files
// shared with them. Nobody else can see it and nothing legitimate needs it.
//
// Taking the bait is detected wherever the canary turns up again:
//
//   copied       the page saw a canary on the clipboard (fingerprints only - see shared-files.js)
//   exfiltrated  a canary appeared in text written somewhere, e.g. a project description
//   key_used     a canary was presented as a credential to one of the trap endpoints
//
// A trip is recorded in honeytoken_triggers - which the scoring job reads and floors the next
// score at 100 - and the identity throttle freezes the account of everyone involved (the person
// the decoy was planted for, and whoever presented the canary), so signing back in waits for an
// admin. The report goes to the console and to onTrip. Canaries stay armed after a decoy is
// rotated or withdrawn: a copy taken while it was up is just as damning later.
//
// Uses only the tables in database/crimguard/: resources, honeytokens (placement holds the decoy
// as JSON), honeytoken_triggers and platform_audit_log; identity_actions through the throttle.

const crypto = require('node:crypto');
const { createSubjects, redIdOf } = require('../telemetry/subjects');
const { createEvents } = require('../telemetry/events');
const { POLICY, decide } = require('./policy');
const { chooseLure, canaryContext } = require('./lures');
const { generateCanary, extractCandidates, fingerprint, isFingerprint } = require('./canaries');
const { latestScore } = require('../identity/scores');

// Shared-file ids live in their own range, clear of real projects and of the decoy projects in
// src/telemetry/honeytokens.js (900,000,000+).
const FILE_ID_BASE = 800_000_000;
const URI_PREFIX = 'red:honeytrap/';
const PREFIX_LENGTH = 8;
const PREFIX_COUNT = 12;
const DUPLICATE_WINDOW_MS = 60 * 60 * 1000;
const SEARCH_LOOKBACK_DAYS = 30;

const INTERACTION_ACTION = { copied: 'copy', exfiltrated: 'download', key_used: 'read', opened: 'read' };
const CLIPBOARD_INTERACTION = { copy: 'copied', cut: 'copied', paste: 'copied', upload: 'exfiltrated', share: 'exfiltrated' };

const uriFor = (crimUserId, planting) => `${URI_PREFIX}${crimUserId}/${planting}`;
const parseJson = (value) => {
  if (value && typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return null; }
};

function createHoneytrap(db, {
  identity = null,
  policy = POLICY,
  now = Date.now,
  random = crypto.randomBytes,
  jitter = Math.random,
  secret = crypto.randomBytes(32),
  onTrip = null,
  log = announce,
} = {}) {
  if (!db) return createDisabled();
  if (!identity) throw new Error('Honeytrapping needs the identity throttle to act on a trip.');

  const subjects = createSubjects(db);
  const events = createEvents(db);
  const iso = (ms = now()) => new Date(ms).toISOString();

  // --- plantings ---------------------------------------------------------------------------------

  function toPlanting(row) {
    const placement = parseJson(row.placement) || {};
    return {
      honeytokenId: Number(row.id),
      resourceId: Number(row.resource_id),
      crimUserId: Number(String(row.uri).slice(URI_PREFIX.length).split('/')[0]),
      active: row.is_active === true || row.is_active === 1,
      plantedAt: row.planted_at,
      retiredAt: row.retired_at,
      tokenType: row.token_type,
      ...placement,
    };
  }

  async function plantings({ crimUserId = null, activeOnly = false } = {}) {
    const org = await subjects.organization();
    const { rows } = await db.query(
      `SELECT ht.id, ht.is_active, ht.planted_at, ht.retired_at, ht.token_type, ht.placement, r.id AS resource_id, r.uri
       FROM honeytokens ht JOIN resources r ON r.id = ht.resource_id
       WHERE ht.org_id = ? AND r.uri LIKE ?${activeOnly ? ' AND ht.is_active = ?' : ''}
       ORDER BY ht.id`,
      [org, crimUserId === null ? `${URI_PREFIX}%` : `${URI_PREFIX}${crimUserId}/%`, ...(activeOnly ? [true] : [])],
    );
    return rows.map(toPlanting);
  }

  // fingerprint -> planting, across every canary this organisation has ever planted.
  let index = null;
  async function fingerprintIndex() {
    if (index) return index;
    const map = new Map();
    for (const planting of await plantings()) {
      for (const fp of planting.fingerprints || []) map.set(fp, planting);
    }
    index = map;
    return index;
  }
  const invalidate = () => { index = null; };

  // --- what we know about the person -----------------------------------------------------------

  async function profileOf(crimUserId) {
    const [person, searches, risk, trips, previous] = await Promise.all([
      db.query(
        `SELECT u.id, u.okta_user_id, u.job_title, u.is_privileged, d.name AS department, o.name AS org_name
         FROM users u JOIN organizations o ON o.id = u.org_id LEFT JOIN departments d ON d.id = u.department_id
         WHERE u.id = ?`,
        [crimUserId],
      ),
      db.query(
        `SELECT search_query FROM file_access_events
         WHERE user_id = ? AND search_query IS NOT NULL AND occurred_at >= ?
         ORDER BY occurred_at DESC LIMIT 50`,
        [crimUserId, iso(now() - SEARCH_LOOKBACK_DAYS * 86400000)],
      ),
      latestScore(db, crimUserId),
      db.query('SELECT occurred_at FROM honeytoken_triggers WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 1', [crimUserId]),
      plantings({ crimUserId }),
    ]);

    const row = person.rows[0];
    if (!row) return null;
    const topFeatures = (risk?.payload.contributions || [])
      .filter((c) => c.points > 0 && c.feature)
      .sort((a, b) => b.points - a.points)
      .slice(0, 5)
      .map((c) => c.feature);

    return {
      crimUserId,
      redUserId: redIdOf(row.okta_user_id),
      role: row.is_privileged ? 'admin' : 'user',
      jobTitle: row.job_title,
      department: row.department,
      orgName: row.org_name,
      searchTerms: searches.rows.map((r) => r.search_query),
      score: risk ? risk.score : null,
      level: risk?.level ?? null,
      scenario: risk?.scenario ?? null,
      topFeatures,
      lastTripAt: trips.rows[0]?.occurred_at ?? null,
      recentThemes: previous.slice(-5).map((p) => p.theme).filter(Boolean),
      plantings: previous,
    };
  }

  // --- planting and withdrawing -----------------------------------------------------------------

  async function plant(profile, tier) {
    const active = profile.plantings.filter((p) => p.active);
    const choice = chooseLure(profile, { tier, jitter, exclude: active.map((p) => p.theme) });
    if (!choice) return null;
    const { lure, reasons } = choice;
    const canary = generateCanary(lure.canary, canaryContext(lure, profile), { random });

    const org = await subjects.organization();
    const planting = profile.plantings.length + 1;
    const plantedAt = iso();
    // The date the file claims to have been last updated: a few weeks back, so it doesn't look
    // like it appeared the moment someone went looking. planted_at itself stays truthful.
    const displayUpdatedAt = iso(now() - (7 + Math.floor(jitter() * 50)) * 86400000);

    const { rows: resource } = await db.query(
      `INSERT INTO resources (org_id, resource_type, uri, display_name, sensitivity, criticality_weight, is_honeytoken)
       VALUES (?, 'file', ?, ?, 'restricted', 5, ?) RETURNING id`,
      [org, uriFor(profile.crimUserId, planting), lure.title, true],
    );
    const placement = {
      honeytrap: 1,
      theme: lure.theme,
      tier, // the policy tier it was planted under; lureTier is how valuable the decoy itself is
      lureTier: lure.tier,
      title: lure.title,
      description: lure.description,
      fileName: canary.fileName,
      body: canary.body,
      canaryKind: canary.kind,
      fingerprints: canary.fingerprints,
      displayUpdatedAt,
      reasons,
      planted: { score: profile.score, level: profile.level, scenario: profile.scenario },
    };
    const { rows: token } = await db.query(
      `INSERT INTO honeytokens (org_id, resource_id, token_type, token_fingerprint, placement, is_active, planted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
      [org, resource[0].id, canary.tokenType, canary.fingerprints[0], JSON.stringify(placement), true, plantedAt],
    );
    await audit('honeytrap_planted', Number(token[0].id), {
      subject: profile.crimUserId, theme: lure.theme, tier, reasons, score: profile.score, scenario: profile.scenario,
    });
    invalidate();
    return { honeytokenId: Number(token[0].id), theme: lure.theme, tier, title: lure.title, reasons };
  }

  async function retire(planting, reason) {
    const placement = { ...stripPlanting(planting), retireReason: reason };
    await db.query('UPDATE honeytokens SET is_active = ?, retired_at = ?, placement = ? WHERE id = ? AND is_active = ?',
      [false, iso(), JSON.stringify(placement), planting.honeytokenId, true]);
    await audit('honeytrap_retired', planting.honeytokenId, { subject: planting.crimUserId, reason, theme: planting.theme });
    invalidate();
  }

  async function audit(action, honeytokenId, details) {
    const org = await subjects.organization();
    await db.query(
      `INSERT INTO platform_audit_log (org_id, action, target_table, target_id, details, occurred_at)
       VALUES (?, ?, 'honeytokens', ?, ?, ?)`,
      [org, action, honeytokenId, JSON.stringify(details), iso()],
    );
  }

  // Applies the policy to one person. `override` lets a caller pass a score it just computed.
  async function evaluate(crimUserId, override = {}) {
    const profile = await profileOf(Number(crimUserId));
    if (!profile) return null;
    Object.assign(profile, override);

    const active = profile.plantings.filter((p) => p.active);
    const decision = decide({
      score: profile.score, scenario: profile.scenario, lastTripAt: profile.lastTripAt, now: now(),
      active: active.map((p) => ({ id: p.honeytokenId, tier: p.tier, plantedAt: p.plantedAt })),
    }, policy);

    const retired = [];
    for (const { id, reason } of decision.retire) {
      const planting = active.find((p) => p.honeytokenId === id);
      await retire(planting, reason);
      planting.active = false;
      retired.push({ honeytokenId: id, reason, theme: planting.theme });
    }
    const planted = decision.plant ? await plant(profile, decision.tier) : null;
    return { crimUserId: profile.crimUserId, score: profile.score, scenario: profile.scenario, tier: decision.tier, planted, retired };
  }

  // Everyone in the organisation who has a score. Meant to run after the scoring job.
  async function evaluateAll() {
    const org = await subjects.organization();
    const { rows } = await db.query(
      `SELECT DISTINCT u.id FROM users u JOIN risk_scores r ON r.user_id = u.id WHERE u.org_id = ? ORDER BY u.id`, [org],
    );
    const results = [];
    for (const { id } of rows) results.push(await evaluate(id));
    return {
      people: results.length,
      planted: results.filter((r) => r?.planted).length,
      retired: results.reduce((n, r) => n + (r?.retired.length ?? 0), 0),
      results,
    };
  }

  // --- the trip ------------------------------------------------------------------------------------

  async function trip(planting, { interaction, via, presentedBy = null, client = {}, extra = {} }) {
    const at = iso();
    const owner = planting.crimUserId;

    const involved = [...new Set([owner, presentedBy].filter((id) => id !== null && id !== undefined))];
    // The same canary seen again from the same person within the hour is one incident, not two.
    // Someone else handling it is a new one, for them.
    const { rows: recent } = await db.query(
      `SELECT DISTINCT user_id FROM honeytoken_triggers
       WHERE honeytoken_id = ? AND interaction = ? AND occurred_at >= ? AND user_id IN (${involved.map(() => '?').join(', ')})`,
      [planting.honeytokenId, interaction, iso(now() - DUPLICATE_WINDOW_MS), ...involved],
    );
    const seen = new Set(recent.map((row) => Number(row.user_id)));
    const targets = involved.filter((id) => !seen.has(id));
    const { rows: people } = await db.query(
      `SELECT id, okta_user_id, full_name, email FROM users WHERE id IN (${involved.map(() => '?').join(', ')})`, involved,
    );
    const ownerRow = people.find((p) => Number(p.id) === owner) || {};

    const report = {
      at,
      decoy: planting.title,
      theme: planting.theme,
      tier: planting.tier,
      interaction,
      via,
      owner: { crimUserId: owner, redUserId: redIdOf(ownerRow.okta_user_id), name: ownerRow.full_name, email: ownerRow.email },
      presentedBy: presentedBy !== null && presentedBy !== owner ? presentedBy : null,
      ip: client.ip || null,
      plantedFor: planting.planted || null,
      redUserIds: [],
      duplicate: targets.length === 0,
    };
    if (report.duplicate) return report;

    const details = JSON.stringify({ via, theme: planting.theme, decoy: planting.title, userAgent: client.userAgent || null, ...extra });
    for (const userId of targets) {
      await db.query(
        `INSERT INTO honeytoken_triggers (honeytoken_id, user_id, occurred_at, interaction, source_ip, details)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [planting.honeytokenId, userId, at, interaction, client.ip || null,
          userId === owner ? details : JSON.stringify({ ...JSON.parse(details), plantedFor: owner })],
      );
      await events.fileAccess({ userId, resourceId: planting.resourceId, action: INTERACTION_ACTION[interaction] || 'read', occurredAt: at, filePath: planting.fileName });
      const response = await identity.respond({
        crimUserId: userId, action: 'session_freeze', source: 'honeytrap',
        reasons: [`${interaction} via ${via}`, `decoy "${planting.title}"`, ...(userId === owner ? [] : [`planted for CrimGuard user ${owner}`])],
      });
      // Only accounts whose sessions were actually ended: the last admin gets a step-up instead.
      if (response?.redUserId !== null && response?.redUserId !== undefined) report.redUserIds.push(response.redUserId);
    }
    if (planting.active) await retire(planting, 'tripped');
    await audit('honeytrap_tripped', planting.honeytokenId, { owner, presentedBy: report.presentedBy, interaction, via });

    log(report);
    if (onTrip) {
      try { onTrip(report); } catch { /* a listener must not turn the trip into an error */ }
    }
    return report;
  }

  // Trips every planting any of `fingerprints` belongs to. Returns the reports.
  async function tripMatches(fingerprints, options) {
    const known = await fingerprintIndex();
    const hits = new Map();
    for (const fp of fingerprints) {
      const planting = known.get(fp);
      if (planting) hits.set(planting.honeytokenId, planting);
    }
    const reports = [];
    for (const planting of hits.values()) reports.push(await trip(planting, options));
    return reports.filter((r) => !r.duplicate);
  }

  // --- the surfaces --------------------------------------------------------------------------------

  async function ownPlanting(user, fileId) {
    const crimUserId = await subjects.lookupUser(user.id);
    if (crimUserId === null) return null;
    const honeytokenId = Number(fileId) - FILE_ID_BASE;
    return (await plantings({ crimUserId, activeOnly: true })).find((p) => p.honeytokenId === honeytokenId) || null;
  }

  return {
    enabled: true,
    policy,
    evaluate,
    evaluateAll,

    // The decoys shared with this account, shaped as ordinary files.
    async filesFor(user) {
      const crimUserId = await subjects.lookupUser(user.id);
      if (crimUserId === null) return [];
      return (await plantings({ crimUserId, activeOnly: true })).map((p) => ({
        id: FILE_ID_BASE + p.honeytokenId,
        name: p.title,
        fileName: p.fileName,
        description: p.description,
        updatedAt: p.displayUpdatedAt,
        size: Buffer.byteLength(p.body || ''),
      }));
    },

    // Opening one: recorded as an access to a restricted file, and a trip only under the strict policy.
    async openFile({ user, fileId, client = {} }) {
      const planting = await ownPlanting(user, fileId);
      if (!planting) return null;
      if (policy.tripOn.includes('opened')) {
        const report = await trip(planting, { interaction: 'opened', via: 'shared_file', presentedBy: planting.crimUserId, client });
        return { tripped: true, report };
      }
      await events.fileAccess({ userId: planting.crimUserId, resourceId: planting.resourceId, action: 'read', occurredAt: iso(), filePath: planting.fileName });
      return { tripped: false, file: { id: FILE_ID_BASE + planting.honeytokenId, name: planting.title, fileName: planting.fileName, body: planting.body } };
    },

    // Fingerprint prefixes the page watches the clipboard for. The same list for every account -
    // every canary the organisation has armed, padded with prefixes derived from a server secret -
    // so nobody can tell from it whether a decoy is theirs, or whether they have one at all. Only
    // a clipboard string whose hash starts with one of these is ever reported, and the server
    // checks the full fingerprint.
    async watchList() {
      const prefixes = new Set([...(await fingerprintIndex()).keys()].map((fp) => fp.slice(0, PREFIX_LENGTH)));
      for (let i = 0; prefixes.size < PREFIX_COUNT || i < PREFIX_COUNT; i++) {
        prefixes.add(crypto.createHmac('sha256', secret).update(`watch:${i}`).digest('hex').slice(0, PREFIX_LENGTH));
      }
      return [...prefixes].sort();
    },

    // The page matched something on the clipboard against the watch list.
    async sighting({ user, action, fingerprints, client = {} }) {
      const interaction = CLIPBOARD_INTERACTION[action];
      const valid = Array.isArray(fingerprints) ? fingerprints.filter(isFingerprint).slice(0, 50) : [];
      if (!interaction || !valid.length) return [];
      const presentedBy = await subjects.forUser(user);
      return tripMatches(valid, { interaction, via: `clipboard_${action}`, presentedBy, client });
    },

    // Text someone wrote into Red, checked on the server. For the routes that save text.
    async inspectText({ user, text, channel = 'text', client = {} }) {
      const candidates = extractCandidates(text);
      if (!candidates.length) return [];
      const presentedBy = user ? await subjects.forUser(user) : null;
      return tripMatches(candidates.map(fingerprint), { interaction: 'exfiltrated', via: channel, presentedBy, client });
    },

    // Credentials presented to a trap endpoint, from anyone - no session needed. The canary
    // itself says whose decoy it was.
    async presentedCredentials({ values, via, user = null, client = {} }) {
      const candidates = new Set();
      for (const value of values) {
        if (typeof value !== 'string' || !value) continue;
        candidates.add(value.trim());
        for (const found of extractCandidates(value)) candidates.add(found);
      }
      if (!candidates.size) return [];
      const presentedBy = user ? await subjects.forUser(user) : null;
      return tripMatches([...candidates].map(fingerprint), { interaction: 'key_used', via, presentedBy, client });
    },

    // Every planting for one person, for the console.
    async report(crimUserId) {
      const list = await plantings({ crimUserId: Number(crimUserId) });
      const { rows: triggers } = await db.query(
        'SELECT honeytoken_id, interaction, occurred_at, source_ip, details FROM honeytoken_triggers WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 100',
        [Number(crimUserId)],
      );
      return {
        plantings: list.map((p) => ({
          honeytokenId: p.honeytokenId, active: p.active, theme: p.theme, tier: p.tier, lureTier: p.lureTier, title: p.title, canaryKind: p.canaryKind,
          reasons: p.reasons, planted: p.planted, plantedAt: p.plantedAt, retiredAt: p.retiredAt, retireReason: p.retireReason ?? null,
        })),
        trips: triggers.map((t) => ({
          honeytokenId: Number(t.honeytoken_id), interaction: t.interaction, at: t.occurred_at, ip: t.source_ip, details: parseJson(t.details),
        })),
      };
    },

    // Re-runs evaluateAll every `intervalMs`. Returns a function that stops it.
    schedule(intervalMs, { onError = (err) => console.error('Honeytrap:', err.message) } = {}) {
      const timer = setInterval(() => { evaluateAll().catch(onError); }, intervalMs);
      timer.unref();
      return () => clearInterval(timer);
    },
  };
}

// The placement JSON without the fields toPlanting() adds.
function stripPlanting(planting) {
  const { honeytokenId, resourceId, crimUserId, active, plantedAt, retiredAt, tokenType, ...placement } = planting;
  void honeytokenId; void resourceId; void crimUserId; void active; void plantedAt; void retiredAt; void tokenType;
  return placement;
}

function announce(report) {
  const line = '═'.repeat(72);
  const who = report.owner.name ? `${report.owner.name} <${report.owner.email}>` : `CrimGuard user ${report.owner.crimUserId}`;
  console.warn(`\n${line}
  HONEYTRAP TRIPPED — sessions revoked
${line}
  Decoy planted for  ${who}
  Decoy              ${report.decoy} (${report.theme}, tier ${report.tier})
  What happened      ${report.interaction} via ${report.via}${report.presentedBy ? ` — presented by CrimGuard user ${report.presentedBy}` : ''}
  From               ${report.ip || 'unknown address'}
  At                 ${report.at}
${line}\n`);
}

function createDisabled() {
  const none = async () => [];
  return {
    enabled: false,
    policy: POLICY,
    evaluate: async () => null,
    evaluateAll: async () => ({ people: 0, planted: 0, retired: 0, results: [] }),
    filesFor: none,
    openFile: async () => null,
    watchList: async () => [],
    sighting: none,
    inspectText: none,
    presentedCredentials: none,
    report: async () => null,
    schedule: () => () => {},
  };
}

module.exports = { createHoneytrap, FILE_ID_BASE, URI_PREFIX };
