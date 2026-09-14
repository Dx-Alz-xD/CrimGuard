'use strict';

const { dayNumber, decay, clamp } = require('./stats');

// How confident we are that the context ledger legitimately explains one anomalous feature.
//
//   confidence = min(maxConfidence, max over ledger items of  reliability × timing × scope × proportion)
//
// reliability  what kind of item it is: an approved ticket is stronger than a project membership
// timing       1 while the item is active; 0 for activity before the item existed; decays after it ends
// scope        share of the touched resources the item covers (ticket_resource_scope, entitlements)
// proportion   1 while observed ≤ 1.25 × what the item says to expect, then (1.25 / ratio)²
//
// The best single item wins rather than items adding up: two weak excuses aren't one strong one.

const NONE = Object.freeze({ confidence: 0, source: null, ref: null, factors: null });

function covers(explains, meta, defaultCategories) {
  if (Array.isArray(explains) && explains.length) return explains.includes(meta.key) || explains.includes(meta.category);
  return defaultCategories == null || defaultCategories.includes(meta.category);
}

function proportion(meta, observed, baselineMedian, item, P) {
  if (meta.valueType === 'flag') return { value: 1, ratio: null };
  let expected = null;
  if (meta.key === 'files_accessed_count' && item.expectedDailyFileVolume > 0) expected = item.expectedDailyFileVolume;
  else if (item.expectedAccessMultiplier > 0 && baselineMedian > 0) expected = item.expectedAccessMultiplier * baselineMedian;
  if (!(expected > 0)) return { value: P.unknownProportion, ratio: null };

  const ratio = observed / expected;
  return { value: ratio <= P.proportionTolerance ? 1 : (P.proportionTolerance / ratio) ** 2, ratio };
}

function ticketTiming(ticket, t, P) {
  if (ticket.status === 'cancelled') return 0;
  const start = dayNumber(ticket.assignedAt ?? ticket.openedAt);
  if (t < start - P.graceDaysBeforeAssignment) return 0;
  const ends = [ticket.unassignedAt, ticket.closedAt ?? ticket.dueAt].filter(Boolean).map(dayNumber);
  if (!ends.length) return 1;
  const end = Math.min(...ends);
  return t <= end ? 1 : decay(t - end, P.ticketAfterEndHalfLifeDays);
}

function projectTiming(project, t) {
  const start = Math.max(...[project.joinedOn, project.startsOn].filter(Boolean).map(dayNumber));
  const ends = [project.leftOn, project.endsOn].filter(Boolean).map(dayNumber);
  if (Number.isFinite(start) && t < start) return 0;
  return ends.length && t > Math.min(...ends) ? 0 : 1;
}

function roleChangeTiming(change, t, P) {
  const age = t - dayNumber(change.validFrom);
  return age < 0 || age > P.roleChangeMaxAgeDays ? 0 : decay(age, P.roleChangeHalfLifeDays);
}

function contextConfidence({ meta, observed, baselineMedian, date, context, snapshotFeatures }, P) {
  if (!meta.contextExplainable) return NONE;
  const t = dayNumber(date);
  let best = NONE;

  const consider = (source, ref, reliability, timing, item) => {
    if (timing <= 0) return;
    const scope = clamp(item.scopeCoverage ?? P.unknownScope, 0, 1);
    const prop = proportion(meta, observed, baselineMedian, item, P);
    const confidence = reliability * timing * scope * prop.value;
    if (confidence > best.confidence) {
      best = { confidence, source, ref, factors: { reliability, timing, scope, proportion: prop.value, ratio: prop.ratio } };
    }
  };

  for (const ticket of context?.tickets ?? []) {
    if (!covers(ticket.explains, meta, P.ticketCategories)) continue;
    const reliability = ticket.approved ? P.reliability.approvedTicket : P.reliability.unapprovedTicket;
    consider('ticket', ticket.key ?? null, reliability, ticketTiming(ticket, t, P), ticket);
  }
  for (const project of context?.projects ?? []) {
    if (!covers(project.explains, meta, P.projectCategories)) continue;
    consider('project', project.name ?? null, P.reliability.project, projectTiming(project, t), project);
  }
  for (const change of context?.roleChanges ?? []) {
    if (!covers(change.explains, meta, null)) continue;
    consider('role_change', change.role ?? null, P.reliability.roleChange, roleChangeTiming(change, t, P), change);
  }

  // A snapshot may only carry the mitigator flags, with no ledger rows behind them.
  if (best.confidence < P.snapshotMitigator
    && (snapshotFeatures?.recent_role_change_flag === true || snapshotFeatures?.recent_project_assignment_flag === true)) {
    best = { confidence: P.snapshotMitigator, source: 'snapshot_flag', ref: null, factors: null };
  }

  return best.confidence > 0 ? { ...best, confidence: Math.min(best.confidence, P.maxConfidence) } : NONE;
}

module.exports = { contextConfidence };
