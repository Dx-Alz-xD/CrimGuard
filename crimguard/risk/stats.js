'use strict';

const DAY_MS = 24 * 60 * 60 * 1000;

// Whole days since the Unix epoch, from 'YYYY-MM-DD', an ISO timestamp or a Date.
// Timestamps are cut to their UTC date, the same day a daily snapshot is filed under.
function dayNumber(value) {
  const ms = value instanceof Date ? value.getTime() : Date.parse(String(value).slice(0, 10));
  if (Number.isNaN(ms)) throw new TypeError(`Not a date: ${value}`);
  return Math.floor(ms / DAY_MS);
}

const decay = (ageDays, halfLifeDays) => 2 ** (-ageDays / halfLifeDays);

const isNumber = (v) => typeof v === 'number' && Number.isFinite(v);

function median(values) {
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

// Median and a robust σ estimate. 1.4826 · MAD equals σ for normal data (Iglewicz & Hoaglin).
// When over half the values are identical MAD is 0, so fall back to 1.2533 · mean absolute
// deviation, which also equals σ for normal data.
function robustStats(values) {
  const m = median(values);
  const deviations = values.map((v) => Math.abs(v - m));
  const mad = median(deviations);
  const scale = mad > 0 ? 1.4826 * mad : 1.2533 * (deviations.reduce((a, b) => a + b, 0) / values.length);
  return { median: m, scale, n: values.length };
}

// Variance-stabilising transforms, so one z-score threshold means the same thing for 3 files a day
// and for 3,000. Anscombe (1948) makes Poisson counts roughly normal with σ ≈ 1. Heavy-tailed volumes
// and durations use Tukey's started log, log(1 + x / c): "×2" is the same distance at any size above
// c (10 MB, 1 minute), while going from 2 MB to 6 MB stays too small to matter.
const TRANSFORMS = {
  count: (x) => 2 * Math.sqrt(Math.max(0, x) + 3 / 8),
  volume_mb: (x) => Math.log1p(Math.max(0, x) / 10),
  seconds: (x) => Math.log1p(Math.max(0, x) / 60),
  ratio: (x) => x,
  score: (x) => x,
};

function scaleFloor(valueType, center, floors) {
  const f = floors[valueType] ?? { abs: 1e-6 };
  return Math.max(f.abs ?? 0, (f.rel ?? 0) * Math.abs(center));
}

// Keeps only the tail the catalog marks as suspicious (anomaly_direction).
function directional(z, direction) {
  if (direction === 'low') return Math.max(0, -z);
  if (direction === 'both') return Math.abs(z);
  return Math.max(0, z);
}

// One-sided tabular CUSUM (Page, 1954) over standardised values. Returns the statistic after the
// last value: it grows by (z − k) each day the series sits above the reference and resets at 0.
function cusum(zs, k) {
  let s = 0;
  for (const z of zs) s = Math.max(0, s + z - k);
  return s;
}

// Φ⁻¹(p), the standard normal quantile (Acklam's rational approximation, relative error < 1.2e-9).
const A = [-3.969683028665376e1, 2.209460984245205e2, -2.759285104469687e2, 1.38357751867269e2, -3.066479806614716e1, 2.506628277459239];
const B = [-5.447609879822406e1, 1.615858368580409e2, -1.556989798598866e2, 6.680131188771972e1, -1.328068155288572e1];
const C = [-7.784894002430293e-3, -3.223964580411365e-1, -2.400758277161838, -2.549732539343734, 4.374664141464968, 2.938163982698783];
const D = [7.784695709041462e-3, 3.224671290700398e-1, 2.445134137142996, 3.754408661907416];
const P_LOW = 0.02425;

function inverseNormalCdf(p) {
  if (!(p > 0 && p < 1)) {
    if (p === 0) return -Infinity;
    if (p === 1) return Infinity;
    throw new RangeError(`p must be in [0, 1], got ${p}`);
  }
  if (p < P_LOW || p > 1 - P_LOW) {
    const q = Math.sqrt(-2 * Math.log(p < P_LOW ? p : 1 - p));
    const x = (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
      / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1);
    return p < P_LOW ? x : -x;
  }
  const q = p - 0.5;
  const r = q * q;
  return (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
    / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1);
}

// ln Γ(x), Lanczos approximation (g = 7, n = 9).
const LANCZOS = [0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313,
  -176.61502916214059, 12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];

function logGamma(x) {
  if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - logGamma(1 - x);
  const y = x - 1;
  let a = LANCZOS[0];
  for (let i = 1; i < LANCZOS.length; i++) a += LANCZOS[i] / (y + i);
  const t = y + 7.5;
  return 0.5 * Math.log(2 * Math.PI) + (y + 0.5) * Math.log(t) - t + Math.log(a);
}

// Continued fraction for the incomplete beta function (modified Lentz, as in Numerical Recipes).
function betaContinuedFraction(a, b, x) {
  const tiny = 1e-300;
  let c = 1;
  let d = 1 - ((a + b) * x) / (a + 1);
  d = 1 / (Math.abs(d) < tiny ? tiny : d);
  let h = d;
  for (let m = 1; m <= 300; m++) {
    for (const aa of [(m * (b - m) * x) / ((a + 2 * m - 1) * (a + 2 * m)), (-(a + m) * (a + b + m) * x) / ((a + 2 * m) * (a + 2 * m + 1))]) {
      d = 1 + aa * d;
      d = 1 / (Math.abs(d) < tiny ? tiny : d);
      c = 1 + aa / c;
      if (Math.abs(c) < tiny) c = tiny;
      h *= d * c;
    }
    if (Math.abs(d * c - 1) < 3e-14) break;
  }
  return h;
}

// Iₓ(a, b), the regularised incomplete beta function.
function regularizedBeta(x, a, b) {
  if (x <= 0) return 0;
  if (x >= 1) return 1;
  const front = Math.exp(logGamma(a + b) - logGamma(a) - logGamma(b) + a * Math.log(x) + b * Math.log1p(-x));
  return x < (a + 1) / (a + b + 2)
    ? (front * betaContinuedFraction(a, b, x)) / a
    : 1 - (front * betaContinuedFraction(b, a, 1 - x)) / b;
}

// P(T > t) for Student's t with ν degrees of freedom.
function studentTSurvival(t, nu) {
  const tail = 0.5 * regularizedBeta(nu / (nu + t * t), nu / 2, 0.5);
  return t >= 0 ? tail : 1 - tail;
}

// A z-score measured against a spread estimated from few days is less trustworthy than the same
// z against a known spread. Treat it as Student's t with ν degrees of freedom and return the normal
// z-score with the same tail probability. ν = Infinity leaves z unchanged.
function tToZ(t, nu) {
  if (!(t > 0) || !Number.isFinite(nu)) return t;
  return -inverseNormalCdf(Math.max(studentTSurvival(t, Math.max(nu, 1)), 1e-300));
}

// Turns a z-score into an anomaly strength between 0 and 1:  A = 1 − 2^(−u²),  u = (z − zMin) / (θ − zMin).
// Nothing at or below zMin, exactly 0.5 at the feature's threshold θ, 0.94 one threshold-width
// above it. Squaring u keeps sub-threshold noise small (A = 0.16 halfway to θ) and saturates fast
// above θ.
function anomalyStrength(z, threshold, zMin) {
  if (!(z > zMin)) return 0;
  const u = (z - zMin) / Math.max(threshold - zMin, 0.1);
  return 1 - 2 ** -(u * u);
}

// Combines independent pieces of evidence, each a probability-like value in [0, 1]:
// 1 − Π(1 − rᵢ). Bounded, and never less than its largest input.
function noisyOr(values) {
  let keep = 1;
  for (const v of values) keep *= 1 - Math.min(1, Math.max(0, v));
  return 1 - keep;
}

const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const round = (v, places) => (v == null ? null : Math.round(v * 10 ** places) / 10 ** places);

module.exports = {
  DAY_MS, dayNumber, decay, isNumber, median, robustStats, TRANSFORMS, scaleFloor, directional, cusum,
  inverseNormalCdf, studentTSurvival, tToZ, anomalyStrength, noisyOr, clamp, round,
};
