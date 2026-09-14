'use strict';

// Reproducible synthetic users for the tests and demo.js: the deck's Case A and Case B, plus an
// ordinary user for measuring false positives. Weekdays only, like a real office snapshot feed.

const { DAY_MS, dayNumber, median } = require('./stats');

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function sampler(seed) {
  const rand = mulberry32(seed);
  const normal = () => Math.sqrt(-2 * Math.log(1 - rand())) * Math.cos(2 * Math.PI * rand());
  const poisson = (mean) => {
    if (mean > 30) return Math.max(0, Math.round(mean + Math.sqrt(mean) * normal()));
    const limit = Math.exp(-mean);
    let k = 0;
    for (let p = rand(); p > limit; p *= rand()) k++;
    return k;
  };
  return {
    rand,
    normal,
    poisson,
    uniformInt: (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1)),
    logNormal: (med, sigma) => Math.round(med * Math.exp(sigma * normal()) * 10) / 10,
  };
}

const isoDate = (d) => new Date(d * DAY_MS).toISOString().slice(0, 10);
const addDays = (date, n) => isoDate(dayNumber(date) + n);

function weekdays(start, calendarDays) {
  const out = [];
  for (let i = 0; i < calendarDays; i++) {
    const d = dayNumber(start) + i;
    const weekday = new Date(d * DAY_MS).getUTCDay();
    if (weekday !== 0 && weekday !== 6) out.push(isoDate(d));
  }
  return out;
}

// An ordinary analyst: ~15 files a day, some confidential database work, small downloads.
function ordinaryFeatures(s, overrides = {}) {
  return {
    files_accessed_count: s.poisson(15),
    distinct_resource_types_touched: s.poisson(3),
    confidential_resource_access_count: s.poisson(4),
    daily_download_volume_mb: s.logNormal(40, 0.35),
    external_upload_volume_mb: s.logNormal(2, 0.5),
    after_hours_access_frequency: Math.min(1, Math.max(0, Math.round((0.06 + 0.02 * s.normal()) * 1000) / 1000)),
    first_time_resource_access_flag: s.rand() < 0.1,
    failed_login_attempt_count: s.poisson(0.3),
    usb_write_activity_count: 0,
    weekend_holiday_access_flag: false,
    ...overrides,
  };
}

const START = '2026-01-05';

function buildOrdinary({ seed = 7, calendarDays = 365 } = {}) {
  const s = sampler(seed);
  return { subject: {}, days: weekdays(START, calendarDays).map((date) => ({ date, assetWeight: 4, features: ordinaryFeatures(s) })) };
}

// Case A: 10–20 files a day, then assigned an approved database migration and pulls 500–800 a day.
function buildCaseA({ seed = 11, withTicket = true } = {}) {
  const s = sampler(seed);
  const migrationStart = addDays(START, 150);
  const ticket = {
    key: 'DBM-142', approved: true, status: 'in_progress',
    openedAt: addDays(migrationStart, -3), assignedAt: addDays(migrationStart, -1), dueAt: addDays(migrationStart, 45),
    expectedDailyFileVolume: 600, expectedAccessMultiplier: 15, scopeCoverage: 0.95,
  };
  const days = weekdays(START, 180).map((date) => {
    const migrating = date >= migrationStart;
    const features = migrating
      ? ordinaryFeatures(s, {
        files_accessed_count: s.uniformInt(500, 800),
        distinct_resource_types_touched: s.poisson(5),
        confidential_resource_access_count: s.poisson(40),
        daily_download_volume_mb: s.logNormal(650, 0.2),
        first_time_resource_access_flag: s.rand() < 0.5,
      })
      : ordinaryFeatures(s);
    return { date, assetWeight: 4, features, context: withTicket ? { tickets: [ticket] } : {} };
  });
  return { subject: {}, days, migrationStart, ticket };
}

// Case B: ~15 files a day creeping to ~70 over three months, with nothing on file to explain it.
function buildCaseB({ seed = 23 } = {}) {
  const s = sampler(seed);
  const creepStart = addDays(START, 180);
  const creepDays = 90;
  const days = weekdays(START, 180 + creepDays).map((date) => {
    const progress = Math.max(0, Math.min(1, (dayNumber(date) - dayNumber(creepStart)) / creepDays));
    return { date, assetWeight: 4, features: ordinaryFeatures(s, { files_accessed_count: s.poisson(15 + 55 * progress) }) };
  });
  return { subject: {}, days, creepStart };
}

// What a classic UEBA rule does: flag when today is ≥ 3σ above the mean of the last 30 days.
function classicUebaFlags(days, feature, { windowDays = 30, z = 3 } = {}) {
  return days.map((day, i) => {
    const t = dayNumber(day.date);
    const past = days.slice(0, i).filter((d) => dayNumber(d.date) >= t - windowDays).map((d) => d.features[feature]);
    if (past.length < 7) return { date: day.date, z: null, flagged: false };
    const mean = past.reduce((a, b) => a + b, 0) / past.length;
    const sd = Math.sqrt(past.reduce((a, b) => a + (b - mean) ** 2, 0) / (past.length - 1)) || 1;
    const score = (day.features[feature] - mean) / sd;
    return { date: day.date, z: score, flagged: score >= z };
  });
}

const percentile = (values, p) => {
  const s = [...values].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(p * s.length))];
};

module.exports = { sampler, addDays, weekdays, ordinaryFeatures, buildOrdinary, buildCaseA, buildCaseB, classicUebaFlags, percentile, median };
