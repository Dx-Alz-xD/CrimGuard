'use strict';

// Prints how the risk formula scores the deck's cases next to a classic 3σ UEBA rule.
//   node crimguard/risk/demo.js

const { createRiskEngine, loadFeatureCatalog } = require('.');
const { buildCaseA, buildCaseB, buildOrdinary, classicUebaFlags, percentile } = require('./scenarios');

const engine = createRiskEngine({ catalog: loadFeatureCatalog() });

function explain(result) {
  console.log(`  ${result.date}  score ${result.finalScore.toFixed(1)}  ${result.riskLevel.toUpperCase()}  scenario: ${result.scenario ?? '-'}`);
  for (const c of result.contributions.slice(0, 4)) {
    const parts = [`${c.points.toFixed(1).padStart(5)} pts  ${c.feature}`];
    if (c.observed != null) parts.push(`observed ${c.observed} vs median ${c.baselineMedian}`);
    if (c.detector) parts.push(`${c.detector} z=${c.z[c.detector === 'drift' ? 'drift' : 'self']}`);
    if (c.driftPctVsAnchor != null && c.detector === 'drift') parts.push(`+${Math.round(c.driftPctVsAnchor * 100)}% vs anchor`);
    if (c.context?.source) parts.push(`explained ${Math.round(c.context.confidence * 100)}% by ${c.context.source} ${c.context.ref}`);
    if (c.carriedFrom) parts.push(`carried from ${c.carriedFrom}`);
    console.log(`    ${parts.join(' · ')}`);
  }
}

function classicOn(days, date) {
  const flag = classicUebaFlags(days, 'files_accessed_count').find((d) => d.date === date);
  return `classic 3σ rule: z=${flag.z.toFixed(1)} ${flag.flagged ? 'FLAGGED' : 'not flagged'}`;
}

console.log('\nCase A: database migration, 500–800 files/day, approved ticket DBM-142');
const caseA = buildCaseA();
const a = engine.scoreTimeline(caseA).filter((r) => r.date >= caseA.migrationStart);
console.log(`  ${classicOn(caseA.days, caseA.migrationStart)}`);
explain(a[0]);
const noTicket = buildCaseA({ withTicket: false });
console.log('  same activity with no ticket on file:');
explain(engine.scoreTimeline(noTicket).find((r) => r.date === noTicket.migrationStart));

console.log('\nCase B: 15 → 70 files/day over three months, nothing on file');
const caseB = buildCaseB();
const b = engine.scoreTimeline(caseB);
const firstHigh = b.find((r) => r.date >= caseB.creepStart && r.riskLevel === 'high');
console.log(`  first high-risk day: ${firstHigh?.date ?? 'none'}`);
console.log(`  ${classicOn(caseB.days, b.at(-1).date)}`);
explain(b.at(-1));

console.log('\nOrdinary users (false positives, Mar–Dec, 5 synthetic users)');
for (const seed of [7, 8, 9, 10, 11]) {
  const scores = engine.scoreTimeline(buildOrdinary({ seed })).filter((r) => r.date >= '2026-03-01').map((r) => r.finalScore);
  const count = (min) => scores.filter((s) => s >= min).length;
  console.log(`  user ${seed}: median ${percentile(scores, 0.5).toFixed(1)}  p95 ${percentile(scores, 0.95).toFixed(1)}  max ${Math.max(...scores).toFixed(1)}  medium+ ${count(40)}/${scores.length}  high+ ${count(70)}`);
}
console.log();
