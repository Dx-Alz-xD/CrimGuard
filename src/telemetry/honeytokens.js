'use strict';

// Decoys. Once an account's risk score crosses a threshold, a fake project appears in its
// list - named to look like exactly the thing someone hoarding data would reach for. It is
// visible to that account alone, and nothing legitimate ever needs to touch it.
//
// Reading it is not proof of anything: a curious person opens it, sees nothing, and moves on.
// Trying to *change* or *delete* it is the trip, and that is deliberate - it takes an
// intention that no ordinary use of Red produces.
//
// A trip does three things: records it (honeytoken_triggers, which floors the next risk score
// at 100), revokes every session the account has (identity_actions, the schema's own response
// action), and prints the whole thing to the server console.

const crypto = require('node:crypto');

// Decoy projects live in their own id range so they can never collide with a real project.
const DECOY_ID_BASE = 900_000_000;
const DEFAULT_PLANT_SCORE = 40;

const isDecoyId = (id) => Number(id) >= DECOY_ID_BASE;

// Deliberately dull, plausible names: the point is that they read as a real thing someone
// forgot to lock down, not as a trap.
const DECOYS = [
  {
    name: 'Production API keys (do not share)',
    description: 'AWS + Stripe live keys for the production account. Rotated quarterly — see credentials.env attached.',
    type: 'fake_api_key',
  },
  {
    name: 'Payroll & compensation — all staff FY25',
    description: 'Salary bands, bonus multipliers and equity grants for every employee. Restricted: finance and HR only.',
    type: 'canary_document',
  },
  {
    name: 'Customer master list + contacts export',
    description: 'Full customer export with contract values and named contacts. Do not remove from the platform.',
    type: 'honey_file',
  },
  {
    name: 'Credentials vault backup',
    description: 'Recovery copy of the shared credential store, including service account passwords.',
    type: 'fake_credential',
  },
];

// Each planting gets its own uri, so a retired decoy never blocks the next one: both
// resources.uri and honeytokens.token_fingerprint are unique per organisation.
const uriFor = (redUserId, planting) => `red:honeytoken/${redUserId}/${planting}`;
const prefixFor = (redUserId) => `red:honeytoken/${redUserId}/`;

// Which decoy a planting uses. Rotating means someone who tripped one and came back doesn't
// see the same name sitting there again.
const decoyFor = (redUserId, planting) => DECOYS[(redUserId + planting) % DECOYS.length];

function createHoneytokens(db, { subjects, events, plantScore = DEFAULT_PLANT_SCORE, onTrip = null } = {}) {
  // The decoy is only useful if it looks like it has been sitting there a while.
  const plantedAt = (days) => new Date(Date.now() - days * 86400000).toISOString();

  // Plants one decoy for an account that has crossed the threshold, if it has none already.
  // Returns the decoy, or null when nothing was planted.
  async function plantIfNeeded(redUserId, score) {
    if (!Number.isFinite(score) || score < plantScore) return null;
    const existing = await activeFor(redUserId);
    if (existing.length) return null;

    const org = await subjects.organization();
    // Count every decoy this account has ever had, retired ones included, so the new one
    // lands on a uri and fingerprint nothing else is using.
    const { rows: previous } = await db.query(
      'SELECT COUNT(*) AS n FROM resources WHERE org_id = ? AND uri LIKE ?',
      [org, `${prefixFor(redUserId)}%`],
    );
    const planting = Number(previous[0]?.n ?? 0) + 1;
    const decoy = decoyFor(redUserId, planting);
    const uri = uriFor(redUserId, planting);

    await db.query(
      `INSERT INTO resources (org_id, resource_type, uri, display_name, sensitivity, criticality_weight, is_honeytoken)
       VALUES (?, 'file', ?, ?, 'restricted', 5, ?) ON CONFLICT DO NOTHING`,
      [org, uri, decoy.name, true],
    );
    const { rows } = await db.query('SELECT id FROM resources WHERE org_id = ? AND uri = ?', [org, uri]);
    if (!rows.length) return null;
    const resourceId = rows[0].id;

    const fingerprint = crypto.createHash('sha256').update(`honeytoken:${uri}`).digest('hex').slice(0, 32);
    await db.query(
      `INSERT INTO honeytokens (org_id, resource_id, token_type, token_fingerprint, placement, is_active, planted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
      [org, resourceId, decoy.type, fingerprint, uri, true, plantedAt(9)],
    );
    return (await activeFor(redUserId))[0] ?? null;
  }

  // The decoys planted for one account, shaped like the projects the dashboard already renders
  // so there is nothing about them that gives the game away.
  async function activeFor(redUserId) {
    const org = await subjects.organization();
    const { rows } = await db.query(
      `SELECT ht.id, ht.planted_at, r.id AS resource_id, r.uri, r.display_name
       FROM honeytokens ht JOIN resources r ON r.id = ht.resource_id
       WHERE ht.org_id = ? AND ht.is_active = ? AND r.uri LIKE ?
       ORDER BY ht.id`,
      [org, true, `${prefixFor(redUserId)}%`],
    );

    return rows.map((row) => {
      const decoy = decoyFor(redUserId, Number(row.uri.split('/').pop()));
      return {
        honeytokenId: row.id,
        resourceId: row.resource_id,
        project: {
          id: DECOY_ID_BASE + row.id,
          name: decoy.name,
          description: decoy.description,
          status: 'active',
          created_at: row.planted_at,
          updated_at: row.planted_at,
        },
      };
    });
  }

  // Someone touched a decoy. `interaction` is 'opened' for a read, or 'modified' / 'deleted'
  // for the ones that count as taking the bait.
  async function trip({ user, decoyId, interaction, client = {}, tokenHash = null }) {
    const honeytokenId = Number(decoyId) - DECOY_ID_BASE;
    const org = await subjects.organization();
    const { rows } = await db.query(
      `SELECT ht.id, ht.resource_id, r.uri, r.display_name FROM honeytokens ht
       JOIN resources r ON r.id = ht.resource_id
       WHERE ht.id = ? AND ht.org_id = ? AND ht.is_active = ?`,
      [honeytokenId, org, true],
    );
    if (!rows.length) return null;
    const token = rows[0];
    // A decoy belongs to exactly one account; anyone else reaching it is a different problem.
    if (!token.uri.startsWith(prefixFor(user.id))) return null;

    const crimUserId = await subjects.forUser(user);
    const at = new Date().toISOString();

    await db.query(
      `INSERT INTO honeytoken_triggers (honeytoken_id, user_id, occurred_at, interaction, source_ip, details)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [token.id, crimUserId, at, interaction, client.ip || null,
        JSON.stringify({ resource: token.display_name, userAgent: client.userAgent || null })],
    );

    // The decoy has done its job; leaving it live would only collect duplicates.
    await db.query('UPDATE honeytokens SET is_active = ?, retired_at = ? WHERE id = ?', [false, at, token.id]);

    // Record the access itself too, so the day's feature snapshot shows what was touched.
    await events.fileAccess({
      userId: crimUserId, resourceId: token.resource_id,
      action: interaction === 'deleted' ? 'delete' : 'write', occurredAt: at, filePath: token.display_name,
    });

    // The score as it stood when they took the bait, before the trip floors it at 100.
    const { rows: scores } = await db.query(
      `SELECT r.final_score, r.risk_level, r.scenario FROM risk_scores r
       JOIN risk_feature_snapshot s ON s.id = r.snapshot_id
       WHERE r.user_id = ? ORDER BY s.snapshot_date DESC, r.scored_at DESC LIMIT 1`,
      [crimUserId],
    );
    const score = scores[0] || null;

    // Freeze the sessions on record and log the response, the way 07_detection_scoring.sql
    // expects an automated action to be logged.
    await db.query('UPDATE user_sessions SET is_frozen = ? WHERE user_id = ? AND ended_at IS NULL', [true, crimUserId]);
    await db.query('UPDATE user_sessions SET ended_at = ? WHERE user_id = ? AND ended_at IS NULL', [at, crimUserId]);
    await db.query(
      `INSERT INTO identity_actions (user_id, action, provider, status, request_payload, created_at, completed_at)
       VALUES (?, 'session_revoke', 'red', 'completed', ?, ?, ?)`,
      [crimUserId, JSON.stringify({ reason: 'honeytoken_trip', honeytokenId: token.id, interaction }), at, at],
    );

    const report = {
      at,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
      decoy: token.display_name,
      interaction,
      ip: client.ip || null,
      score: score ? Number(score.final_score) : null,
      level: score ? score.risk_level : null,
      scenario: score ? score.scenario : null,
    };
    announce(report);
    if (onTrip) {
      try { onTrip(report); } catch { /* a listener must not turn the response into an error */ }
    }
    void tokenHash;
    return report;
  }

  return { plantIfNeeded, activeFor, trip, plantScore };
}

// Printed straight to the server console, which is where the operator is watching.
function announce(report) {
  const line = '═'.repeat(72);
  const score = report.score === null ? 'not yet scored' : `${report.score.toFixed(1)} (${report.level})`;
  console.warn(`\n${line}
  HONEYTOKEN TRIPPED — session revoked
${line}
  User          ${report.user.name} <${report.user.email}>  [${report.user.role}, Red id ${report.user.id}]
  Risk score    ${score}${report.scenario ? ` · ${report.scenario.replace(/_/g, ' ')}` : ''}
  Decoy         ${report.decoy}
  Action        ${report.interaction}
  From          ${report.ip || 'unknown address'}
  At            ${report.at}

  Every session for this account has been revoked and the person signed out
  everywhere. The next risk score for them is floored at 100 (critical).
${line}\n`);
}

module.exports = { createHoneytokens, isDecoyId, DECOY_ID_BASE, DECOYS, DEFAULT_PLANT_SCORE };
