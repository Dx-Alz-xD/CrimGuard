'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  inverseNormalCdf, studentTSurvival, tToZ, robustStats, anomalyStrength, noisyOr, TRANSFORMS, cusum, dayNumber,
} = require('../../crimguard/risk/stats');
const { sampler } = require('../../crimguard/risk/scenarios');

const close = (actual, expected, tolerance, label) =>
  assert.ok(Math.abs(actual - expected) <= tolerance, `${label ?? ''} expected ${expected} ± ${tolerance}, got ${actual}`);

test('the inverse normal CDF matches published quantiles', () => {
  for (const [p, z] of [[0.5, 0], [0.975, 1.959963985], [0.99, 2.326347874], [0.001, -3.090232306], [1e-10, -6.361340902]]) {
    close(inverseNormalCdf(p), z, 1e-6, `p=${p}`);
  }
});

test('Student t tails are right, and converting to z only ever shrinks a z-score', () => {
  close(studentTSurvival(1, 1), 0.25, 1e-9, 'Cauchy');
  close(studentTSurvival(2.228138852, 10), 0.025, 1e-7, 't(10) 97.5% quantile');
  close(studentTSurvival(0, 5), 0.5, 1e-12);

  assert.equal(tToZ(3, Infinity), 3);
  close(tToZ(3, 1e6), 3, 1e-3, 'huge ν is normal');
  assert.ok(tToZ(3, 5) < tToZ(3, 20) && tToZ(3, 20) < 3, 'fewer degrees of freedom, smaller z');
  assert.ok(Number.isFinite(tToZ(500, 3)), 'extreme values stay finite');
  assert.equal(tToZ(0, 5), 0);
});

test('the robust baseline ignores outliers and survives a MAD of zero', () => {
  const s = robustStats([10, 11, 9, 10, 12, 8, 10, 1000]);
  assert.equal(s.median, 10);
  close(s.scale, 1.4826, 1e-9);

  const flat = robustStats([5, 5, 5, 5, 6]);
  close(flat.scale, 1.2533 * 0.2, 1e-9, 'mean absolute deviation fallback');
});

test('anomaly strength is 0 up to zMin, 0.5 at the threshold, and saturates above it', () => {
  assert.equal(anomalyStrength(1.5, 2.6, 1.5), 0);
  assert.equal(anomalyStrength(-4, 2.6, 1.5), 0);
  close(anomalyStrength(2.6, 2.6, 1.5), 0.5, 1e-12);
  close(anomalyStrength(3.7, 2.6, 1.5), 1 - 2 ** -4, 1e-12);
  let previous = 0;
  for (let z = 1.6; z < 10; z += 0.1) {
    const a = anomalyStrength(z, 2.6, 1.5);
    assert.ok(a >= previous && a <= 1, `z=${z}`);
    previous = a;
  }
});

test('the Anscombe transform gives Poisson counts a spread of about 1 at any mean', () => {
  const s = sampler(99);
  for (const mean of [4, 15, 60]) {
    const y = Array.from({ length: 5000 }, () => TRANSFORMS.count(s.poisson(mean)));
    const m = y.reduce((a, b) => a + b, 0) / y.length;
    const sd = Math.sqrt(y.reduce((a, b) => a + (b - m) ** 2, 0) / (y.length - 1));
    close(sd, 1, 0.08, `mean ${mean}`);
  }
});

test('noisy-OR is bounded and never below its largest input', () => {
  assert.equal(noisyOr([]), 0);
  close(noisyOr([0.5, 0.5]), 0.75, 1e-12);
  assert.equal(noisyOr([1, 0.2]), 1);
  assert.ok(noisyOr([0.3, 0.1, 0.05]) >= 0.3);
});

test('CUSUM accumulates a sustained shift and ignores noise around the reference', () => {
  assert.equal(cusum([0.3, -0.2, 0.4, 0.1, -0.5], 0.5), 0);
  close(cusum([2, 2, 2, 2], 0.5), 6, 1e-12);
});

test('dates become whole UTC days whatever form they come in', () => {
  assert.equal(dayNumber('2026-09-14'), dayNumber('2026-09-14T23:59:59Z'));
  assert.equal(dayNumber(new Date('2026-09-15T00:00:00Z')) - dayNumber('2026-09-14'), 1);
  assert.throws(() => dayNumber('not a date'), TypeError);
});
