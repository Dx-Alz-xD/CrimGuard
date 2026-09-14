'use strict';

// The risk score each account currently carries, and who has had limiting switched off.
//
// Scores are computed in the CrimGuard database, which the website talks to asynchronously.
// File visibility, though, is decided in SQL against red.db (see db/files.js), so the score has
// to be readable from that same query - hence the copy kept here, refreshed after every
// scoring run.

const { capFor, describe, TIERS } = require('../security/limits');

function createRiskStore(db) {
  const q = {
    // The score for one day replaces whatever was there: only the latest matters for access.
    setState: db.prepare(`
      INSERT INTO user_risk_state (user_id, score, level, scenario, scored_on, updated_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT (user_id) DO UPDATE SET
        score = excluded.score, level = excluded.level, scenario = excluded.scenario,
        scored_on = excluded.scored_on, updated_at = excluded.updated_at`),
    state: db.prepare('SELECT user_id, score, level, scenario, scored_on, updated_at FROM user_risk_state WHERE user_id = ?'),
    clearState: db.prepare('DELETE FROM user_risk_state WHERE user_id = ?'),

    exemption: db.prepare(`
      SELECT user_id, set_by, set_by_name, set_by_role, reason, created_at
      FROM risk_limit_exemptions WHERE user_id = ?`),
    exempt: db.prepare(`
      INSERT INTO risk_limit_exemptions (user_id, set_by, set_by_name, set_by_role, reason)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (user_id) DO UPDATE SET
        set_by = excluded.set_by, set_by_name = excluded.set_by_name,
        set_by_role = excluded.set_by_role, reason = excluded.reason,
        created_at = datetime('now')`),
    unexempt: db.prepare('DELETE FROM risk_limit_exemptions WHERE user_id = ?'),

    // The rounded-down average confidentiality of every file, which is the baseline the cap
    // is measured down from. NULL when there are no files to average.
    baseline: db.prepare("SELECT CAST(AVG(confidentiality) AS INTEGER) AS baseline FROM project_files"),

    // Clearance comes from the role, so it is read alongside.
    clearance: db.prepare('SELECT r.clearance FROM users u JOIN roles r ON r.name = u.role WHERE u.id = ?'),
  };

  const baseline = () => q.baseline.get()?.baseline ?? null;

  // Everything the dashboard needs to explain one person's limit: the score behind it, the cap
  // it produces, and whether someone has switched it off.
  function limitFor(userId) {
    const state = q.state.get(userId) ?? null;
    const exemption = q.exemption.get(userId) ?? null;
    const clearance = q.clearance.get(userId)?.clearance ?? null;
    if (clearance === null) return null;

    const base = baseline();
    const applied = capFor({ score: state?.score, clearance, baseline: base, exempt: Boolean(exemption) });
    // What it *would* do if nobody had switched it off, so the dashboard can say what is being
    // waived rather than just that a waiver exists.
    const wouldBe = exemption ? capFor({ score: state?.score, clearance, baseline: base }) : applied;

    return {
      score: state ? Number(state.score) : null,
      level: state?.level ?? null,
      scenario: state?.scenario ?? null,
      scoredOn: state?.scored_on ?? null,
      clearance,
      baseline: base,
      tier: applied.tier?.name ?? null,
      tierLabel: applied.tier?.label ?? null,
      cap: applied.cap,
      limited: applied.limited,
      wouldLimit: wouldBe.limited,
      wouldCap: wouldBe.cap,
      explanation: describe({ ...wouldBe, clearance }),
      exemption: exemption && {
        by: exemption.set_by_name,
        byRole: exemption.set_by_role,
        reason: exemption.reason,
        at: exemption.created_at,
      },
    };
  }

  return {
    TIERS,
    baseline,
    limitFor,
    state: (userId) => q.state.get(userId) ?? null,
    setState: (userId, { score, level, scenario = null, scoredOn }) => {
      q.setState.run(userId, score, level, scenario, scoredOn);
    },
    clearState: (userId) => { q.clearState.run(userId); },
    exemption: (userId) => q.exemption.get(userId) ?? null,
    // Switching limiting off for someone, and back on.
    exempt: (userId, { by, reason = '' }) => {
      q.exempt.run(userId, by.id, by.name, by.role, reason);
    },
    unexempt: (userId) => q.unexempt.run(userId).changes > 0,
  };
}

module.exports = { createRiskStore };
