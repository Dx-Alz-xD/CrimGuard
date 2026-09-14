'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createRiskEngine, toRiskScoreRow, PARAMS, MODEL_VERSION } = require('../../crimguard/risk');
const { hrAmplifier } = require('../../crimguard/risk/amplifier');
const { buildCaseA, buildCaseB, ordinaryFeatures } = require('../../crimguard/risk/scenarios');
const { catalog, engine, userDays, lastDate, scoreAll, scoreLast, contribution, addDays, sampler, weekdays } = require('./risk-helpers');

const migrationTicket = (date, overrides = {}) => ({
  key: 'DBM-9', approved: true, assignedAt: addDays(date, -2), dueAt: addDays(date, 30),
  expectedDailyFileVolume: 600, scopeCoverage: 1, ...overrides,
});

// ----- context -----

test('context is discounted only in proportion: 5× what the ticket expects is barely explained', () => {
  const days = userDays();
  const date = lastDate(days);
  const proportionate = scoreLast(userDays({ edits: { 0: { features: { files_accessed_count: 650 }, context: { tickets: [migrationTicket(date)] } } } }));
  const excessive = scoreLast(userDays({ edits: { 0: { features: { files_accessed_count: 3000 }, context: { tickets: [migrationTicket(date)] } } } }));

  assert.equal(contribution(proportionate, 'files_accessed_count').context.confidence, 0.9);
  const over = contribution(excessive, 'files_accessed_count').context;
  assert.ok(over.factors.ratio === 5 && over.confidence < 0.1, `confidence ${over.confidence}`);
  assert.ok(excessive.finalScore > proportionate.finalScore + 40);
});

test('a ticket assigned after the activity, or cancelled, explains nothing; a closed one fades', () => {
  const date = lastDate(userDays());
  const withTicket = (ticket) => contribution(scoreLast(userDays({
    edits: { 0: { features: { files_accessed_count: 650 }, context: { tickets: [ticket] } } },
  })), 'files_accessed_count').context.confidence;

  assert.equal(withTicket(migrationTicket(date, { assignedAt: addDays(date, 5) })), 0, 'back-dated justification');
  assert.equal(withTicket(migrationTicket(date, { status: 'cancelled' })), 0);
  const closedThreeDaysAgo = withTicket(migrationTicket(date, { assignedAt: addDays(date, -20), closedAt: addDays(date, -3) }));
  assert.ok(Math.abs(closedThreeDaysAgo - 0.5) < 1e-3, `half-life of 3 days: ${closedThreeDaysAgo}`);
  assert.equal(withTicket(migrationTicket(date, { approved: false })), 0.7);
});

test('signals that are never context-explainable ignore tickets entirely', () => {
  const date = lastDate(userDays());
  const ticket = migrationTicket(date, { explains: ['data_movement'] });
  const result = scoreLast(userDays({ edits: { 0: { features: { usb_write_activity_count: 40 }, context: { tickets: [ticket] } } } }));
  const usb = contribution(result, 'usb_write_activity_count');
  assert.equal(usb.context.confidence, 0);
  assert.ok(result.finalScore >= 70, `USB bulk write scored ${result.finalScore}`);
});

test('a recent role change explains new patterns and fades with a 30-day half-life', () => {
  const date = lastDate(userDays());
  const confidence = (daysAgo) => contribution(scoreLast(userDays({
    edits: { 0: { features: { confidential_resource_access_count: 30 }, context: { roleChanges: [{ role: 'DBA', validFrom: addDays(date, -daysAgo), scopeCoverage: 1 }] } } },
  })), 'confidential_resource_access_count').context.confidence;
  assert.ok(Math.abs(confidence(0) - 0.6 * 0.6) < 1e-3, 'reliability 0.6 × unknown proportion 0.6');
  assert.ok(Math.abs(confidence(30) - confidence(0) / 2) < 1e-3);
  assert.equal(confidence(120), 0);
});

// ----- HR amplifier -----

test('the HR amplifier follows departure proximity, decays stressors and caps at 2', () => {
  const date = '2026-06-01';
  const H = (hr, subject = {}) => hrAmplifier({ subject: { hr, ...subject }, date }, PARAMS.hr).value;

  assert.equal(H({}), 1);
  assert.ok(Math.abs(H({ terminationDate: addDays(date, 20) }) - 1.6) < 1e-9);
  assert.ok(Math.abs(H({ terminationDate: addDays(date, 60) }) - 1.3) < 1e-9, 'half-way up the 90 → 30 day ramp');
  assert.equal(H({ terminationDate: addDays(date, 120) }), 1);
  assert.ok(Math.abs(H({ terminationDate: addDays(date, -5) }) - 1.6) < 1e-9, 'still active after the leaving date');

  const review = { type: 'performance_review', isNegative: true, effectiveDate: addDays(date, -45) };
  assert.ok(Math.abs(H({ events: [review] }) - 1.15) < 1e-9, '0.3 halved after 45 days');
  assert.equal(H({ events: [{ ...review, effectiveDate: addDays(date, 10) }] }), 1, 'future reviews do not count yet');
  assert.equal(H({ events: [{ type: 'resignation_notice', effectiveDate: addDays(date, 14), recordedAt: addDays(date, 3) }] }), 1,
    'a resignation HR has not recorded yet is unknown');

  const pileUp = {
    terminationDate: addDays(date, 10),
    events: [review, { type: 'disciplinary_action', effectiveDate: date }],
    leave: [{ requestedAt: date, daysRequested: 18, balanceBefore: 20 }],
  };
  assert.equal(H(pileUp, { employmentType: 'contractor' }), 2);

  const fromFlags = hrAmplifier({ subject: {}, date, features: { pto_dump_flag: true, recent_negative_review_flag: true } }, PARAMS.hr);
  assert.ok(Math.abs(fromFlags.value - 1.55) < 1e-9);
});

test('HR stressors raise existing risk but cannot create risk from nothing', () => {
  const flat = (s) => ({ files_accessed_count: 15, daily_download_volume_mb: 40, usb_write_activity_count: 0 });
  const leaving = { hr: { terminationDate: '2026-06-10', events: [{ type: 'disciplinary_action', effectiveDate: '2026-05-20' }] } };

  const quiet = scoreLast(userDays({ features: flat }), { subject: leaving });
  assert.equal(quiet.finalScore, 0);
  assert.ok(quiet.components.hrAmplifier > 1.5);

  const spike = { 0: { features: { daily_download_volume_mb: 400 } } };
  const base = scoreLast(userDays({ features: flat, edits: spike }));
  const amplified = scoreLast(userDays({ features: flat, edits: spike }), { subject: leaving });
  const H = amplified.components.hrAmplifier;
  const expected = 100 * (1 - (1 - base.finalScore / 100) ** H);
  assert.ok(Math.abs(amplified.finalScore - expected) < 0.05, `${amplified.finalScore} vs ${expected}`);
  assert.equal(amplified.scenario, 'pre_resignation_hoarding');
});

// ----- overrides, sequences, extra evidence -----

test('a honeytoken trip is critical at 100 no matter what explains the rest', () => {
  const date = lastDate(userDays());
  const result = scoreLast(userDays({ edits: { 0: { honeytokenTrips: 1, context: { tickets: [migrationTicket(date)] } } } }));
  assert.equal(result.finalScore, 100);
  assert.equal(result.riskLevel, 'critical');
  assert.equal(result.scenario, 'honeytoken_trip');
  assert.equal(result.components.honeytokenOverride, true);
});

test('audit log tampering is at least high even on an otherwise quiet day', () => {
  const result = scoreLast(userDays({ edits: { 0: { features: { audit_log_modification_flag: true } } } }));
  assert.ok(result.finalScore >= 70);
  assert.equal(result.scenario, 'privilege_abuse');
});

test('each extra stage of collect → stage → exfiltrate on the same day adds risk', () => {
  const collectAndSend = { daily_download_volume_mb: 900, external_upload_volume_mb: 700 };
  const features = (s) => ({ ...ordinaryFeatures(s), pre_transfer_compression_flag: false });
  const twoStages = scoreLast(userDays({ features, edits: { 0: { features: collectAndSend } } }));
  const threeStages = scoreLast(userDays({ features, edits: { 0: { features: { ...collectAndSend, pre_transfer_compression_flag: true } } } }));

  assert.deepEqual(twoStages.exfiltrationSequence, ['collection', 'exfiltration']);
  assert.deepEqual(threeStages.exfiltrationSequence, ['collection', 'staging', 'exfiltration']);
  const seq = (r) => contribution(r, 'exfiltration_sequence').points;
  assert.ok(seq(threeStages) > seq(twoStages));
  assert.ok(threeStages.finalScore > twoStages.finalScore);
});

test('an Isolation Forest score adds risk only once it is clearly anomalous', () => {
  const normal = scoreLast(userDays({ edits: { 0: { isolationForestScore: 0.5 } } }));
  const anomalous = scoreLast(userDays({ edits: { 0: { isolationForestScore: 0.8 } } }));
  assert.equal(contribution(normal, 'multivariate'), undefined);
  assert.ok(contribution(anomalous, 'multivariate').points > 0);
  assert.ok(anomalous.finalScore > normal.finalScore);
});

// ----- accumulation over days -----

test('one sustained anomaly is not re-counted every day', () => {
  const spikes = Object.fromEntries([0, 1, 2, 3, 4].map((i) => [i, { features: { usb_write_activity_count: 40 } }]));
  const last5 = scoreAll(userDays({ edits: spikes })).slice(-5).map((r) => r.finalScore);
  assert.ok(Math.max(...last5.slice(1)) <= last5[0] + 0.5, `scores ${last5.join(', ')}`);
});

test('different signals on different days add up, then fade', () => {
  const usbThenConfidential = { 1: { features: { usb_write_activity_count: 40 } }, 0: { features: { confidential_resource_access_count: 30 } } };
  const both = scoreLast(userDays({ edits: usbThenConfidential }));
  const aloneToday = scoreLast(userDays({ edits: { 0: { features: { confidential_resource_access_count: 30 } } } }));

  const carried = contribution(both, 'usb_write_activity_count');
  assert.ok(carried.carriedFrom, 'yesterday\'s USB write still counts today');
  assert.ok(both.finalScore > aloneToday.finalScore + 20);

  // Two quiet weeks later nothing is carried.
  const days = userDays({ edits: { 10: { features: { usb_write_activity_count: 40 } } } });
  assert.equal(contribution(scoreLast(days), 'usb_write_activity_count'), undefined);
});

// ----- baselines -----

test('a new user is judged against their peer group until they have their own history', () => {
  const s = sampler(5);
  const days = weekdays('2026-05-04', 5).map((date) => ({ date, assetWeight: 4, features: { files_accessed_count: s.poisson(15) } }));
  days.at(-1).features.files_accessed_count = 70;
  const peers = { files_accessed_count: Array.from({ length: 40 }, () => s.poisson(15)) };

  const withPeers = scoreLast(days, { peers });
  const files = contribution(withPeers, 'files_accessed_count');
  assert.ok(files.ownWeight > 0 && files.ownWeight < 0.5, `own history weight ${files.ownWeight}`);
  assert.ok(files.strength > 0.9);

  const alone = scoreLast(days);
  assert.equal(contribution(alone, 'files_accessed_count'), undefined, 'four days of history is too little to judge');
  assert.equal(alone.dataQuality.lowConfidence, true);
});

test('a first-ever weekend login is surprising; for a weekend worker it is routine', () => {
  const neverWeekends = scoreLast(userDays({ edits: { 0: { features: { weekend_holiday_access_flag: true } } } }));
  assert.ok(contribution(neverWeekends, 'weekend_holiday_access_flag').strength > 0.5);

  const weekendWorker = scoreLast(userDays({
    features: (s) => ({ files_accessed_count: s.poisson(15), weekend_holiday_access_flag: s.rand() < 0.3 }),
    edits: { 0: { features: { weekend_holiday_access_flag: true } } },
  }));
  assert.equal(contribution(weekendWorker, 'weekend_holiday_access_flag'), undefined);
});

test('features that were not collected are skipped, not treated as zero', () => {
  const result = scoreLast(userDays({ edits: { 0: { features: { files_accessed_count: null, confidential_resource_access_count: 30 } } } }));
  assert.equal(contribution(result, 'files_accessed_count'), undefined);
  assert.ok(result.dataQuality.featuresMissing > 0 && result.dataQuality.coverage < 1);
});

test('org settings can switch a feature off or lower its weight', () => {
  const caseB = buildCaseB();
  const off = createRiskEngine({ catalog, orgSettings: { files_accessed_count: { isEnabled: false } } });
  const light = createRiskEngine({ catalog, orgSettings: { files_accessed_count: { weight: 0.3 } } });
  const full = engine.scoreTimeline(caseB).at(-1).finalScore;
  const lighter = light.scoreTimeline(caseB).at(-1).finalScore;
  assert.ok(lighter < full - 30, `${lighter} vs ${full}`);
  assert.ok(off.scoreTimeline(caseB).at(-1).finalScore < 40);
});

// ----- explanation and storage -----

test('per-feature points add up to the final score', () => {
  const results = [
    ...engine.scoreTimeline(buildCaseA()).slice(-5),
    ...engine.scoreTimeline(buildCaseB()).slice(-5),
    scoreLast(userDays({ edits: { 0: { honeytokenTrips: 1 } } })),
    scoreLast(userDays({ edits: { 1: { features: { usb_write_activity_count: 40 } }, 0: { features: { external_upload_volume_mb: 500 } } } })),
  ];
  for (const r of results) {
    const total = r.contributions.reduce((sum, c) => sum + c.points, 0);
    assert.ok(Math.abs(total - r.finalScore) < 0.05 * Math.max(1, r.contributions.length), `${r.date}: ${total} vs ${r.finalScore}`);
  }
});

test('risk_scores rows satisfy the table constraints and serialise cleanly', () => {
  const levels = ['low', 'medium', 'high', 'critical'];
  const scenarios = [null, 'legitimate_spike', 'slow_exfiltration', 'pre_resignation_hoarding', 'shadow_ai_leak',
    'credential_compromise', 'privilege_abuse', 'honeytoken_trip', 'physical_security', 'other'];
  const results = [
    ...engine.scoreTimeline(buildCaseA()),
    ...engine.scoreTimeline(buildCaseA({ withTicket: false })).slice(-3),
    ...engine.scoreTimeline(buildCaseB()).slice(-3),
    scoreLast(userDays({ edits: { 0: { honeytokenTrips: 1 } } }), { subject: { hr: { terminationDate: '2026-06-10' } } }),
  ];

  const finite = (value, path) => {
    if (typeof value === 'number') assert.ok(Number.isFinite(value), `${path} is ${value}`);
    else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) finite(v, `${path}.${k}`);
  };

  for (const r of results) {
    const row = toRiskScoreRow(r, { snapshotId: 1, userId: 2 });
    assert.equal(row.model_version, MODEL_VERSION);
    assert.ok(row.final_score >= 0 && row.final_score <= 100 && Number.isInteger(Math.round(row.final_score * 100)));
    assert.ok(row.statistical_anomaly_score >= 0);
    assert.ok(row.drift_score == null || row.drift_score >= 0);
    assert.ok(row.isolation_forest_score == null || (row.isolation_forest_score >= 0 && row.isolation_forest_score <= 1));
    assert.ok(row.asset_criticality_weight > 0 && row.asset_criticality_weight <= 999.99);
    assert.ok(row.context_multiplier >= 0 && row.context_multiplier <= 1);
    assert.ok(row.hr_amplifier >= 1 && row.hr_amplifier <= 99.99);
    assert.ok(levels.includes(row.risk_level));
    assert.ok(scenarios.includes(row.scenario), row.scenario);
    finite(row, 'row');
    assert.doesNotThrow(() => JSON.stringify(row));
  }
});

test('every indicator in the real catalog can be scored without NaN', () => {
  const indicators = engine.indicators;
  assert.equal(catalog.length, 100);
  assert.equal(indicators.length, 90);
  const usb = catalog.find((f) => f.key === 'usb_write_activity_count');
  assert.deepEqual(usb, { key: 'usb_write_activity_count', category: 'data_movement', valueType: 'count', signalRole: 'indicator', direction: 'high', contextExplainable: false, zThreshold: 2.6 });

  const s = sampler(42);
  const value = (f, extreme) => {
    switch (f.valueType) {
      case 'flag': return extreme ? true : s.rand() < 0.05;
      case 'count': return extreme ? 500 : s.poisson(5);
      case 'volume_mb': case 'seconds': return extreme ? 1e6 : s.logNormal(100, 0.5);
      default: return extreme ? (f.direction === 'low' ? 0 : 50) : Math.round(s.rand() * 1000) / 1000;
    }
  };
  const days = weekdays('2026-01-05', 250).map((date, i, all) => ({
    date,
    assetWeight: 3,
    isolationForestScore: s.rand(),
    features: Object.fromEntries(indicators.map((f) => [f.key, value(f, i === all.length - 1)])),
  }));
  const results = engine.scoreTimeline({ days, subject: { isPrivileged: true, employmentType: 'temp', hireDate: '2025-01-01' } });
  for (const r of results) {
    assert.ok(Number.isFinite(r.finalScore) && r.finalScore >= 0 && r.finalScore <= 100, `${r.date}: ${r.finalScore}`);
  }
  assert.equal(results.at(-1).riskLevel, 'critical');
});
