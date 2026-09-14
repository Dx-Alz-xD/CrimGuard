'use strict';

// The scenarios from the pitch deck, end to end, plus the false-positive rate on ordinary users.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { buildCaseA, buildCaseB, buildOrdinary, classicUebaFlags } = require('../../crimguard/risk/scenarios');
const { engine, userDays, scoreLast, contribution } = require('./risk-helpers');

test('a big spike on low-value data ranks below a smaller spike on sensitive data', () => {
  const bigLowValue = scoreLast(userDays({ seed: 3, edits: { 0: { features: { files_accessed_count: 400 }, assetWeight: 1 } } }));
  const smallSensitive = scoreLast(userDays({ seed: 3, edits: { 0: { features: { files_accessed_count: 45 }, assetWeight: 5 } } }));

  const big = contribution(bigLowValue, 'files_accessed_count');
  const small = contribution(smallSensitive, 'files_accessed_count');
  assert.ok(big.z.self > small.z.self, 'the low-value spike is statistically bigger');
  assert.ok(smallSensitive.finalScore > bigLowValue.finalScore + 30,
    `sensitive ${smallSensitive.finalScore} should clearly outrank low-value ${bigLowValue.finalScore}`);
});

test('Case A: an approved migration ticket turns a 40× spike into a low, explained risk', () => {
  const withTicket = buildCaseA();
  const withoutTicket = buildCaseA({ withTicket: false });
  const explained = engine.scoreTimeline(withTicket).filter((r) => r.date >= withTicket.migrationStart);
  const unexplained = engine.scoreTimeline(withoutTicket).filter((r) => r.date >= withoutTicket.migrationStart);

  for (const r of explained) {
    assert.equal(r.riskLevel, 'low', `${r.date} scored ${r.finalScore}`);
    assert.equal(r.scenario, 'legitimate_spike');
  }
  const files = contribution(explained[0], 'files_accessed_count');
  assert.equal(files.context.source, 'ticket');
  assert.equal(files.context.ref, 'DBM-142');
  assert.equal(files.context.confidence, 0.9);
  assert.ok(files.context.factors.ratio < 1.25, 'volume is in line with what the ticket expects');

  for (const r of unexplained) assert.equal(r.riskLevel, 'critical', `${r.date} scored ${r.finalScore}`);

  const classic = classicUebaFlags(withTicket.days, 'files_accessed_count').find((d) => d.date === withTicket.migrationStart);
  assert.equal(classic.flagged, true, 'a classic 3σ rule tickets the first migration day');
});

test('Case B: a slow creep from 15 to 70 files a day is invisible to a rolling baseline but scored high', () => {
  const caseB = buildCaseB();
  const results = engine.scoreTimeline(caseB);
  const lastTwoWeeks = results.slice(-10);

  for (const r of lastTwoWeeks) {
    assert.equal(r.riskLevel, 'high', `${r.date} scored ${r.finalScore}`);
    assert.equal(r.scenario, 'slow_exfiltration');
  }
  const files = contribution(results.at(-1), 'files_accessed_count');
  assert.equal(files.detector, 'drift');
  assert.equal(files.detectionMethod, 'drift_trend');
  assert.ok(files.driftPctVsAnchor > 2.5, `+${Math.round(files.driftPctVsAnchor * 100)}% vs the anchored baseline`);
  assert.ok(files.z.self < 2, 'the daily detector alone sees nothing unusual');

  const classic = classicUebaFlags(caseB.days, 'files_accessed_count').slice(-10);
  assert.ok(classic.every((d) => !d.flagged), 'a classic 3σ rule has absorbed the creep');
});

test('Case B climbs gradually instead of jumping straight to high', () => {
  const caseB = buildCaseB();
  const creep = engine.scoreTimeline(caseB).filter((r) => r.date >= caseB.creepStart);
  const firstMonth = creep.slice(0, 20);
  assert.ok(firstMonth.every((r) => r.riskLevel === 'low' || r.riskLevel === 'medium'), 'a small early increase is not yet high');
  assert.ok(creep.at(-1).finalScore > firstMonth[0].finalScore + 40);
});

test('ordinary users: no high-risk days in a year and medium on at most 2% of days', () => {
  for (const seed of [7, 8, 9, 10, 11]) {
    const ordinary = buildOrdinary({ seed });
    // Skip the first two months, while the baseline is still being learned.
    const results = engine.scoreTimeline(ordinary).filter((r) => r.date >= '2026-03-01');
    const high = results.filter((r) => r.finalScore >= 70);
    const medium = results.filter((r) => r.finalScore >= 40);
    assert.equal(high.length, 0, `seed ${seed}: ${high.map((r) => `${r.date}=${r.finalScore}`).join(', ')}`);
    assert.ok(medium.length <= 0.02 * results.length, `seed ${seed}: ${medium.length} medium days of ${results.length}`);
  }
});
