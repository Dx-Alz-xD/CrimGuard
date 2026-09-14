'use strict';

// Risk limiting: an account whose risk score gets high enough has its clearance cut, so the
// files it can reach shrink until someone looks at why.
//
// The baseline is the average confidentiality of every file in Red, rounded down. From there:
//
//   score >= 75   clearance capped one level below the average
//   score >= 85   two levels below
//
// So with an average of 3, a limited account is held to 2, and a badly limited one to 1.
//
// What it does and does not touch. Only *clearance* is cut, which is what decides the two
// blanket rules in db/files.js: an admin's reach over everything at or below their level, and
// a file shared with a whole role. Owning a file, and having one shared with you by name, are
// not clearance decisions and are left alone - the point is to narrow how wide someone's reach
// is, not to lock them out of their own work mid-sentence.
//
// The cap is applied inside the person() CTE in db/files.js, so every list, download and
// dialog inherits it from the one place the visibility rule is written.

const { MIN_LEVEL } = require('./access');

// Highest threshold first: the first tier an account meets is the one that applies.
const TIERS = Object.freeze([
  Object.freeze({ name: 'tightened', minScore: 85, drop: 2, label: 'Tightened' }),
  Object.freeze({ name: 'reduced', minScore: 75, drop: 1, label: 'Reduced' }),
]);

// A cap of 0 is below the lowest file level, so nothing clearance-based is reachable at all.
const NO_ACCESS = MIN_LEVEL - 1;

const tierFor = (score) => (Number.isFinite(score) ? TIERS.find((tier) => score >= tier.minScore) ?? null : null);

// What an account's clearance becomes. `baseline` is the rounded-down average confidentiality;
// when there are no files to average there is no baseline, and nothing is capped.
function capFor({ score, clearance, baseline, exempt = false }) {
  const tier = exempt ? null : tierFor(score);
  if (!tier || !Number.isFinite(baseline)) {
    return { tier: null, cap: clearance, limited: false, baseline: baseline ?? null };
  }
  const cap = Math.max(NO_ACCESS, Math.min(clearance, baseline - tier.drop));
  return { tier, cap, limited: cap < clearance, baseline };
}

// One line for the dashboard, explaining the cap in the terms an analyst would use.
function describe({ tier, cap, baseline, clearance }) {
  if (!tier) return null;
  const reach = cap <= NO_ACCESS
    ? 'no files through clearance at all'
    : `files up to ${cap}`;
  return `Score ${tier.minScore}+: clearance cut from ${clearance} to ${cap} `
    + `(${tier.drop} below the ${baseline} average), leaving ${reach}.`;
}

module.exports = { TIERS, NO_ACCESS, tierFor, capFor, describe };
