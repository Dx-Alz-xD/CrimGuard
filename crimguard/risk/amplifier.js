'use strict';

const { dayNumber, decay } = require('./stats');

// HR stressors that make the same behaviour more likely to be malicious (CERT insider-threat
// precursors; Purview's HR-connector triggers). Returns H = 1 + boost, boost capped at maxBoost.
//
// The engine applies H as  R' = 1 − (1 − R)^H , so stressors raise existing risk but can't create
// it: a user with no anomalies stays at 0 however bad their review was.

function recentBoost(dates, t, { weight, halfLifeDays, maxAgeDays }) {
  let best = 0;
  for (const date of dates) {
    const age = t - dayNumber(date);
    if (age >= 0 && age <= maxAgeDays) best = Math.max(best, weight * decay(age, halfLifeDays));
  }
  return best;
}

// 1 from 30 days before the departure date onward (and after it, if the account is still active),
// ramping linearly from 0 at 90 days out.
function departureProximity(departureDates, t, { fullWithinDays, rampFromDays }) {
  let best = 0;
  for (const date of departureDates) {
    const daysLeft = dayNumber(date) - t;
    const p = daysLeft <= fullWithinDays ? 1 : daysLeft >= rampFromDays ? 0 : (rampFromDays - daysLeft) / (rampFromDays - fullWithinDays);
    best = Math.max(best, p);
  }
  return best;
}

function hrAmplifier({ subject = {}, date, features = {} }, P) {
  const t = dayNumber(date);
  const factors = [];
  const add = (reason, boost) => { if (boost > 0) factors.push({ reason, boost }); };
  const hr = subject.hr;

  if (hr) {
    // Only what HR knew by the scored day. Departures count ahead of their date; the rest once effective.
    const events = (hr.events ?? []).filter((e) => (e.recordedAt == null || dayNumber(e.recordedAt) <= t)
      && (isDepartureEvent(e) || dayNumber(e.effectiveDate) <= t));
    const of = (predicate) => events.filter(predicate).map((e) => e.effectiveDate);

    const departures = [hr.terminationDate, ...of(isDepartureEvent)].filter(Boolean);
    add('departure', P.departure.weight * departureProximity(departures, t, P.departure));
    add('negative_review', recentBoost(of((e) => e.type === 'performance_review' && e.isNegative), t, P.negativeReview));
    add('disciplinary_action', recentBoost(of((e) => e.type === 'disciplinary_action'), t, P.disciplinary));
    add('compensation_cut', recentBoost(of((e) => e.type === 'compensation_change' && e.isNegative), t, P.compensationCut));
    add('manager_change', recentBoost(of((e) => e.type === 'manager_change'), t, P.managerChange));

    const dumps = (hr.leave ?? []).filter((l) => l.requestedAt && l.daysRequested >= P.ptoDump.minDays
      && l.balanceBefore > 0 && l.daysRequested / l.balanceBefore >= P.ptoDump.minShareOfBalance);
    add('pto_dump', recentBoost(dumps.map((l) => l.requestedAt), t, P.ptoDump));
  } else {
    // Only the snapshot's hr_org_context flags: they already mean "recent", so no decay.
    for (const [key, boost] of Object.entries(P.flagBoosts)) if (features[key] === true) add(key, boost);
    if (features.termination_date_on_file) {
      add('departure', P.departure.weight * departureProximity([features.termination_date_on_file], t, P.departure));
    }
  }

  const employmentType = subject.employmentType ?? features.employment_type;
  if (employmentType === 'contractor' || employmentType === 'temp') add('non_employee', P.nonEmployee);
  if (subject.hireDate) {
    const tenure = t - dayNumber(subject.hireDate);
    if (tenure >= 0 && tenure < P.newHire.withinDays) add('new_hire', P.newHire.weight);
  }

  const boost = Math.min(P.maxBoost, factors.reduce((sum, f) => sum + f.boost, 0));
  return { value: 1 + boost, factors };
}

// A resignation notice or scheduled termination is dated with the leaving day, which is usually in
// the future: that is exactly when it matters.
function isDepartureEvent(e) {
  return e.type === 'resignation_notice' || e.type === 'termination_scheduled' || e.type === 'termination';
}

module.exports = { hrAmplifier };
