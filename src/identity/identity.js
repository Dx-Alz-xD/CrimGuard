'use strict';

// Dynamic identity throttle: the one place CrimGuard acts on an account.
//
// Everything that can end in a step-up or a freeze - a risk score crossing a policy, a change in
// typing and pointer dynamics, a honeytrap trip, failed step-ups - comes through respond(), which
// writes identity_actions (the schema's response log) and carries the action out:
//
//   step_up_mfa     status 'sent' while open. The session (or, for a score policy, every session)
//                   can reach nothing but the step-up until the password is confirmed.
//   session_freeze  status 'completed'. Every Red session ends and signing in is refused until an
//                   admin restores access (restore_access).
//   session_revoke  every session ends; the person may sign in again.
//
// A policy that requires analyst approval records its action as 'pending' and does nothing until
// an admin approves it. State is read back from identity_actions, so it survives a restart and is
// the same in every process that shares the database (after CACHE_MS at most).

const { createEvents } = require('../telemetry/events');
const { sessionRef } = require('../telemetry');
const { DEFAULT_POLICIES, LOCKING, policyFor, standing } = require('./policy');
const { latestScore } = require('./scores');
const { createSubjects, redIdOf } = require('../telemetry/subjects');

const CACHE_MS = 15_000;
const MAX_STEP_UP_FAILURES = 3;

const parse = (value) => {
  if (value && typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return {}; }
};

function createIdentity(db, { stores = null, now = Date.now, onChange = null, log = console.warn } = {}) {
  if (!db) return createDisabled();

  const subjects = createSubjects(db);
  const events = createEvents(db);
  const iso = () => new Date(now()).toISOString();
  const cache = new Map(); // crimUserId -> { at, actions }
  const listeners = { stepUpPassed: [] };

  // --- reading -----------------------------------------------------------------------------

  async function actionsFor(crimUserId, { fresh = false } = {}) {
    const cached = cache.get(crimUserId);
    if (!fresh && cached && now() - cached.at < CACHE_MS) return cached.actions;
    const { rows } = await db.query(
      `SELECT id, action, status, policy_id, requested_by, request_payload, created_at, completed_at
       FROM identity_actions WHERE user_id = ? ORDER BY id DESC LIMIT 100`,
      [crimUserId],
    );
    const actions = rows.map((row) => ({
      id: Number(row.id), action: row.action, status: row.status, policyId: row.policy_id === null ? null : Number(row.policy_id),
      requestedBy: row.requested_by, payload: parse(row.request_payload), createdAt: row.created_at, completedAt: row.completed_at,
    }));
    cache.set(crimUserId, { at: now(), actions });
    return actions;
  }
  const invalidate = (crimUserId) => cache.delete(crimUserId);

  async function redAccountOf(crimUserId) {
    const { rows } = await db.query('SELECT okta_user_id, full_name, email, is_privileged FROM users WHERE id = ?', [crimUserId]);
    const row = rows[0];
    if (!row) return null;
    const redUserId = redIdOf(row.okta_user_id);
    const red = redUserId !== null && stores ? stores.users.findById(redUserId) : null;
    return { redUserId, name: row.full_name, email: row.email, role: red?.role ?? (row.is_privileged ? 'admin' : 'user') };
  }

  // --- policies -----------------------------------------------------------------------------

  let policyCache = null;
  async function policies({ fresh = false } = {}) {
    if (!fresh && policyCache && now() - policyCache.at < CACHE_MS) return policyCache.list;
    const org = await subjects.organization();
    let { rows } = await db.query('SELECT * FROM response_policies WHERE org_id = ? ORDER BY id', [org]);
    if (!rows.length) {
      for (const p of DEFAULT_POLICIES) {
        await db.query(
          `INSERT INTO response_policies (org_id, name, min_final_score, scenario, action, requires_analyst_approval, is_enabled)
           VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
          [org, p.name, p.minFinalScore, p.scenario, p.action, false, true],
        );
      }
      ({ rows } = await db.query('SELECT * FROM response_policies WHERE org_id = ? ORDER BY id', [org]));
    }
    const list = rows.map((row) => ({
      id: Number(row.id), name: row.name, action: row.action, scenario: row.scenario,
      minFinalScore: row.min_final_score === null ? null : Number(row.min_final_score),
      requiresApproval: row.requires_analyst_approval === true || row.requires_analyst_approval === 1,
      isEnabled: row.is_enabled === true || row.is_enabled === 1,
    }));
    policyCache = { at: now(), list };
    return list;
  }

  async function updatePolicy(id, { isEnabled, minFinalScore, requiresApproval }) {
    const current = (await policies({ fresh: true })).find((p) => p.id === Number(id));
    if (!current) return null;
    const next = {
      isEnabled: typeof isEnabled === 'boolean' ? isEnabled : current.isEnabled,
      requiresApproval: typeof requiresApproval === 'boolean' ? requiresApproval : current.requiresApproval,
      minFinalScore: minFinalScore === undefined ? current.minFinalScore : minFinalScore,
    };
    if (next.minFinalScore !== null && !(Number.isFinite(next.minFinalScore) && next.minFinalScore >= 0 && next.minFinalScore <= 100)) {
      throw new RangeError('minFinalScore must be between 0 and 100.');
    }
    if (next.minFinalScore === null && !current.scenario) throw new RangeError('A policy without a scenario needs a minimum score.');
    await db.query('UPDATE response_policies SET is_enabled = ?, requires_analyst_approval = ?, min_final_score = ? WHERE id = ?',
      [next.isEnabled, next.requiresApproval, next.minFinalScore, current.id]);
    policyCache = null;
    return (await policies()).find((p) => p.id === current.id);
  }

  // --- acting --------------------------------------------------------------------------------

  // Ends every Red session of the account. Returns the Red user id, or null.
  function endRedSessions(account, action, details) {
    if (!account || account.redUserId === null || !stores) return null;
    stores.sessions.removeAll(account.redUserId);
    stores.audit.record(`security.identity_${action}`, {
      target: { id: account.redUserId, email: account.email }, details,
    });
    return account.redUserId;
  }

  // A freeze must never lock out the last admin who could lift it: for them it becomes a step-up.
  async function lastAdminStanding(account, crimUserId) {
    if (!stores || account?.role !== 'admin') return false;
    for (const other of stores.users.list().filter((u) => u.role === 'admin' && u.id !== account.redUserId)) {
      const otherCrim = await subjects.lookupUser(other.id);
      if (otherCrim === null || !standing(await actionsFor(otherCrim)).frozen) return false;
    }
    void crimUserId;
    return true;
  }

  async function enforce(crimUserId, action, payload) {
    if (action === 'step_up_mfa') {
      const sessionId = payload.sessionRef ? await events.openSessionId(crimUserId, payload.sessionRef) : null;
      await events.auth({ userId: crimUserId, sessionId, eventType: 'mfa_challenge', occurredAt: iso() });
      return null;
    }
    const at = iso();
    await db.query('UPDATE user_sessions SET is_frozen = ?, ended_at = ? WHERE user_id = ? AND ended_at IS NULL',
      [LOCKING.has(action), at, crimUserId]);
    return endRedSessions(await redAccountOf(crimUserId), action, { source: payload.source, reasons: payload.reasons });
  }

  // The single entry point. Returns { id, action, status, redUserId } - redUserId is set when
  // the account's Red sessions were ended.
  async function respond({
    crimUserId, action, source, reasons = [], sessionRef: ref = null, policyId = null, risk = null,
    requiresApproval = false, requestedBy = null,
  }) {
    crimUserId = Number(crimUserId);
    let effective = action;
    let downgradedFrom = null;
    const account = await redAccountOf(crimUserId);
    if (LOCKING.has(action) && await lastAdminStanding(account, crimUserId)) {
      effective = 'step_up_mfa';
      downgradedFrom = action;
    }

    const payload = {
      source, reasons, sessionRef: effective === 'step_up_mfa' ? ref : null,
      snapshotDate: risk?.snapshotDate ?? null, risk: risk && { score: risk.score, level: risk.level, scenario: risk.scenario },
      ...(downgradedFrom ? { downgradedFrom, note: 'last admin who could restore access' } : {}),
    };
    const status = requiresApproval ? 'pending' : effective === 'step_up_mfa' ? 'sent' : 'completed';
    const at = iso();
    const sessionId = ref ? await events.openSessionId(crimUserId, ref) : null;
    const { rows } = await db.query(
      `INSERT INTO identity_actions (user_id, policy_id, session_id, action, provider, requested_by, status, request_payload, created_at, completed_at)
       VALUES (?, ?, ?, ?, 'red', ?, ?, ?, ?, ?) RETURNING id`,
      [crimUserId, policyId, sessionId, effective, requestedBy, status, JSON.stringify(payload), at, status === 'completed' ? at : null],
    );
    invalidate(crimUserId);

    const redUserId = status === 'pending' ? null : await enforce(crimUserId, effective, payload);
    const result = { id: Number(rows[0].id), crimUserId, action: effective, status, source, reasons, redUserId, account };
    if (effective !== 'step_up_mfa' && status !== 'pending') {
      log(`CrimGuard identity: ${effective} for ${account?.email ?? `user ${crimUserId}`} (${source}: ${reasons.join(', ') || 'no reason given'})`);
    }
    if (onChange) {
      try { onChange(result); } catch { /* a listener must not undo the response */ }
    }
    return result;
  }

  // Applies the response policies to one person's latest score. Nothing fires twice for the
  // same policy and day, and nothing is added to an account that is already frozen.
  async function evaluate(crimUserId) {
    crimUserId = Number(crimUserId);
    const risk = await latestScore(db, crimUserId);
    if (!risk) return null;
    const policy = policyFor(risk, await policies());
    if (!policy) return null;

    const actions = await actionsFor(crimUserId, { fresh: true });
    const state = standing(actions);
    if (state.frozen) return null;
    if (actions.some((a) => a.policyId === policy.id && a.payload.snapshotDate === risk.snapshotDate)) return null;
    if (policy.action === 'step_up_mfa' && state.stepUps.some((a) => !a.payload.sessionRef)) return null;

    return respond({
      crimUserId, action: policy.action, source: 'risk_policy', policyId: policy.id, risk,
      reasons: [`${policy.name}: score ${risk.score.toFixed(1)} (${risk.level}${risk.scenario ? `, ${risk.scenario.replace(/_/g, ' ')}` : ''})`],
      requiresApproval: policy.requiresApproval,
    });
  }

  async function evaluateAll() {
    const org = await subjects.organization();
    const { rows } = await db.query('SELECT DISTINCT r.user_id FROM risk_scores r JOIN users u ON u.id = r.user_id WHERE u.org_id = ?', [org]);
    const results = [];
    for (const { user_id: id } of rows) {
      const result = await evaluate(id);
      if (result) results.push(result);
    }
    return results;
  }

  // --- the person's side -----------------------------------------------------------------------

  // { frozen, stepUp } for a signed-in request.
  async function statusFor(user, tokenHash) {
    const crimUserId = await subjects.lookupUser(user.id);
    if (crimUserId === null) return { frozen: false, stepUp: false };
    const state = standing(await actionsFor(crimUserId), sessionRef(tokenHash));
    return { frozen: state.frozen, stepUp: state.stepUp };
  }

  async function isFrozenRedUser(redUserId) {
    const crimUserId = await subjects.lookupUser(redUserId);
    return crimUserId !== null && standing(await actionsFor(crimUserId, { fresh: true })).frozen;
  }

  // The outcome of a step-up the caller has checked (the password was right or not).
  async function stepUp({ user, tokenHash, passed, client = {} }) {
    const crimUserId = await subjects.lookupUser(user.id);
    if (crimUserId === null) return { status: 'not_required' };
    const ref = sessionRef(tokenHash);
    const open = standing(await actionsFor(crimUserId, { fresh: true }), ref).stepUps;
    if (!open.length) return { status: 'not_required' };
    const sessionId = ref ? await events.openSessionId(crimUserId, ref) : null;
    const at = iso();
    const ids = open.map((a) => a.id);
    const marks = ids.map(() => '?').join(', ');

    if (passed) {
      await events.auth({ userId: crimUserId, sessionId, eventType: 'mfa_success', occurredAt: at, ip: client.ip, userAgent: client.userAgent });
      await db.query(`UPDATE identity_actions SET status = 'completed', completed_at = ? WHERE id IN (${marks})`, [at, ...ids]);
      invalidate(crimUserId);
      for (const listener of listeners.stepUpPassed) listener({ crimUserId, sessionRef: ref, user });
      return { status: 'verified' };
    }

    await events.auth({ userId: crimUserId, sessionId, eventType: 'mfa_failure', occurredAt: at, ip: client.ip, userAgent: client.userAgent });
    const since = open.map((a) => a.createdAt).sort()[0];
    const { rows } = await db.query(
      "SELECT COUNT(*) AS n FROM auth_events WHERE user_id = ? AND event_type = 'mfa_failure' AND occurred_at >= ?", [crimUserId, since],
    );
    const failures = Number(rows[0].n);
    if (failures < MAX_STEP_UP_FAILURES) return { status: 'failed', attemptsLeft: MAX_STEP_UP_FAILURES - failures };

    await db.query(`UPDATE identity_actions SET status = 'failed', completed_at = ? WHERE id IN (${marks})`, [at, ...ids]);
    invalidate(crimUserId);
    const result = await respond({ crimUserId, action: 'session_freeze', source: 'step_up_failed', reasons: [`${failures} wrong passwords`] });
    return { status: result.action === 'session_freeze' ? 'frozen' : 'failed', attemptsLeft: 0 };
  }

  // --- the analyst's side ----------------------------------------------------------------------

  async function adminId(admin) {
    return admin ? subjects.forUser(admin) : null;
  }

  async function approve(actionId, admin) {
    const { rows } = await db.query("SELECT user_id, action, request_payload FROM identity_actions WHERE id = ? AND status = 'pending'", [actionId]);
    if (!rows.length) return null;
    const { user_id: crimUserId, action } = rows[0];
    const status = action === 'step_up_mfa' ? 'sent' : 'completed';
    const at = iso();
    await db.query('UPDATE identity_actions SET status = ?, requested_by = ?, completed_at = ? WHERE id = ?',
      [status, await adminId(admin), status === 'completed' ? at : null, actionId]);
    invalidate(Number(crimUserId));
    const redUserId = await enforce(Number(crimUserId), action, { ...parse(rows[0].request_payload), approvedBy: admin?.email });
    return { id: Number(actionId), action, status, redUserId };
  }

  async function decline(actionId, admin) {
    const { rows } = await db.query("SELECT user_id FROM identity_actions WHERE id = ? AND status = 'pending'", [actionId]);
    if (!rows.length) return null;
    await db.query("UPDATE identity_actions SET status = 'cancelled', requested_by = ?, completed_at = ? WHERE id = ?",
      [await adminId(admin), iso(), actionId]);
    invalidate(Number(rows[0].user_id));
    return { id: Number(actionId), status: 'cancelled' };
  }

  // Lifts a freeze and cancels open step-ups.
  async function restore(crimUserId, admin, note = '') {
    crimUserId = Number(crimUserId);
    const at = iso();
    const open = standing(await actionsFor(crimUserId, { fresh: true }));
    const ids = [...open.stepUps, ...open.pending].map((a) => a.id);
    if (ids.length) {
      await db.query(`UPDATE identity_actions SET status = 'cancelled', completed_at = ? WHERE id IN (${ids.map(() => '?').join(', ')})`, [at, ...ids]);
    }
    await db.query(
      `INSERT INTO identity_actions (user_id, action, provider, requested_by, status, request_payload, created_at, completed_at)
       VALUES (?, 'restore_access', 'red', ?, 'completed', ?, ?, ?)`,
      [crimUserId, await adminId(admin), JSON.stringify({ source: 'analyst', note: String(note).slice(0, 500), by: admin?.email ?? null }), at, at],
    );
    invalidate(crimUserId);
    return { restored: true, wasFrozen: open.frozen, cancelled: ids.length };
  }

  // Accounts under a response now, pending approvals, recent actions and the policies.
  async function overview() {
    const org = await subjects.organization();
    const since = new Date(now() - 30 * 86400000).toISOString();
    const { rows } = await db.query(
      `SELECT DISTINCT a.user_id FROM identity_actions a JOIN users u ON u.id = a.user_id WHERE u.org_id = ? AND a.created_at >= ?`,
      [org, since],
    );
    const people = [];
    for (const { user_id: id } of rows) {
      const crimUserId = Number(id);
      const actions = await actionsFor(crimUserId, { fresh: true });
      const state = standing(actions);
      const account = await redAccountOf(crimUserId);
      const risk = await latestScore(db, crimUserId);
      people.push({
        crimUserId, name: account?.name, email: account?.email, role: account?.role,
        frozen: state.frozen, stepUp: state.stepUp, pending: state.pending.length,
        risk: risk && { score: risk.score, level: risk.level, scenario: risk.scenario },
        actions: actions.slice(0, 10).map(({ id: actionId, action, status, payload, createdAt, completedAt }) => ({
          id: actionId, action, status, source: payload.source, reasons: payload.reasons || [], createdAt, completedAt,
          downgradedFrom: payload.downgradedFrom ?? null,
        })),
      });
    }
    people.sort((a, b) => Number(b.frozen) - Number(a.frozen) || b.pending - a.pending || Number(b.stepUp) - Number(a.stepUp));
    return { policies: await policies(), people };
  }

  return {
    enabled: true,
    policies,
    updatePolicy,
    respond,
    evaluate,
    evaluateAll,
    statusFor,
    isFrozenRedUser,
    stepUp,
    approve,
    decline,
    restore,
    overview,
    standingOf: async (crimUserId, ref = null) => standing(await actionsFor(Number(crimUserId), { fresh: true }), ref),
    onStepUpPassed: (listener) => { listeners.stepUpPassed.push(listener); },
  };
}

function createDisabled() {
  const nothing = async () => null;
  return {
    enabled: false,
    policies: async () => [],
    updatePolicy: nothing,
    respond: nothing,
    evaluate: nothing,
    evaluateAll: async () => [],
    statusFor: async () => ({ frozen: false, stepUp: false }),
    isFrozenRedUser: async () => false,
    stepUp: async () => ({ status: 'not_required' }),
    approve: nothing,
    decline: nothing,
    restore: nothing,
    overview: async () => ({ policies: [], people: [] }),
    standingOf: async () => ({ frozen: false, stepUp: false, stepUps: [], pending: [] }),
    onStepUpPassed: () => {},
  };
}

module.exports = { createIdentity, MAX_STEP_UP_FAILURES, CACHE_MS };
