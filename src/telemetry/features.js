'use strict';

// Turns raw events into the 100 variables for one person on one day.
//
// Every query here is a plain range scan (`occurred_at >= ? AND occurred_at < ?` with ISO
// strings), which means the same thing in SQLite and PostgreSQL. The rollups themselves are
// done in JavaScript rather than SQL: a user-day is a small number of rows, and date
// arithmetic is the part of SQL that differs most between the two.
//
// A variable is only given a value when Red actually has the source for it. Everything
// coverage.js marks 'no-source' stays undefined here, and is written as NULL - which
// 06_feature_snapshots.sql defines as "not collected", not as zero.

const { classifyText } = require('./patterns');
const { isSensitiveUri } = require('./subjects');
const { locate, travelBetween } = require('./geo');
const { dailyDeviation: biometricDeviation } = require('../biometrics/model');

const HISTORY_DAYS = 90;
// The catalog's "vs baseline" variables compare against the rolling 30-day window that
// baseline_window calls rolling_30d, not against everything on file: over a slow ramp a
// 90-day median lags so far behind that the ratio climbs on its own.
const BASELINE_DAYS = 30;
const ROW_LIMIT = 50_000;
const MB = 1024 * 1024;

const BULK_WINDOW_MS = 5 * 60 * 1000;
const BULK_DISTINCT_RESOURCES = 10;
const BURST_SHARE = 0.4;
const BURST_MIN_EVENTS = 20;
const LARGE_COPY_CHARS = 5000;
const RENAME_BEFORE_EXPORT_MS = 60 * 60 * 1000;
const CONCURRENT_GAP_MS = 0;
// How far back to look for a previous sign-in to compare against. Longer than the old
// two-hour window: crossing an ocean takes most of a day, so a jump that only looks
// impossible over a 14-hour gap still needs catching.
const TRAVEL_WINDOW_MS = 24 * 60 * 60 * 1000;
const SENSITIVE = new Set(['confidential', 'restricted']);

// --- small statistics ------------------------------------------------------------

const sum = (values) => values.reduce((total, value) => total + value, 0);
const mean = (values) => (values.length ? sum(values) / values.length : null);

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = sorted.length >> 1;
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function stdev(values) {
  if (values.length < 2) return null;
  const m = mean(values);
  return Math.sqrt(sum(values.map((value) => (value - m) ** 2)) / (values.length - 1));
}

// The most recent `days` entries of a per-day series.
const recent = (values, days = BASELINE_DAYS) => values.slice(-days);

// today / the usual value, with a floor so a quiet baseline doesn't produce a huge ratio.
function ratioToBaseline(today, history, floor) {
  const window = recent(history);
  if (today === null || !window.length) return null;
  return today / Math.max(median(window), floor);
}

// How far today sits from the usual value, in standard deviations. Needs a few days of
// history before it means anything.
function deviation(today, history, floorSpread, minDays = 3) {
  const window = recent(history);
  if (today === null || window.length < minDays) return null;
  const spread = Math.max(stdev(window) ?? 0, floorSpread);
  return Math.abs(today - median(window)) / spread;
}

const dayOf = (iso) => String(iso).slice(0, 10);
const hourOf = (iso) => { const d = new Date(iso); return d.getUTCHours() + d.getUTCMinutes() / 60; };
const msOf = (iso) => Date.parse(iso);
const addDays = (date, days) => new Date(Date.parse(`${date}T00:00:00Z`) + days * 86400000).toISOString().slice(0, 10);
const startOf = (date) => `${date}T00:00:00.000Z`;
const isWeekend = (date) => [0, 6].includes(new Date(`${date}T00:00:00Z`).getUTCDay());

// The difference between two times of day, the short way round the clock.
const hourGap = (a, b) => { const d = Math.abs(a - b) % 24; return Math.min(d, 24 - d); };

// Group values by the day they happened on.
function byDay(rows, at = (row) => row.occurred_at) {
  const days = new Map();
  for (const row of rows) {
    const key = dayOf(at(row));
    if (!days.has(key)) days.set(key, []);
    days.get(key).push(row);
  }
  return days;
}

// The per-day totals of some measure, for every day before today that had any.
const dailyTotals = (days, today, value) =>
  [...days].filter(([date]) => date < today).map(([, rows]) => value(rows));

const ipPrefix = (ip) => {
  if (!ip) return null;
  return ip.includes(':') ? ip.split(':').slice(0, 4).join(':') : ip.split('.').slice(0, 3).join('.');
};

// --- loading ---------------------------------------------------------------------

// Every raw row this person produced from `from` up to `to`, plus their HR timeline.
async function loadWindow(db, userId, from, to) {
  const range = [userId, from, to];
  const scan = async (sql, params = range) => (await db.query(sql, params)).rows;

  const [files, transfers, clipboard, endpoints, auth, biometrics, privilege, network, communication, sessions, biometricWindows] = await Promise.all([
    scan(`SELECT f.occurred_at, f.action, f.bytes, f.resource_id, f.search_query, f.files_in_batch, f.previous_path,
                 r.resource_type, r.sensitivity, r.uri
          FROM file_access_events f LEFT JOIN resources r ON r.id = f.resource_id
          WHERE f.user_id = ? AND f.occurred_at >= ? AND f.occurred_at < ?
          ORDER BY f.occurred_at LIMIT ${ROW_LIMIT}`),
    scan(`SELECT occurred_at, channel, bytes, renamed_before_export, is_compressed FROM data_transfer_events
          WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ? ORDER BY occurred_at LIMIT ${ROW_LIMIT}`),
    scan(`SELECT occurred_at, char_count, detected_patterns, source_app, destination_app FROM clipboard_events
          WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ? ORDER BY occurred_at LIMIT ${ROW_LIMIT}`),
    scan(`SELECT occurred_at, event_type, details FROM endpoint_events
          WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ? ORDER BY occurred_at LIMIT ${ROW_LIMIT}`),
    scan(`SELECT occurred_at, event_type, source_ip, city, country_code, latitude, longitude, user_agent, device_id
          FROM auth_events
          WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ? ORDER BY occurred_at LIMIT ${ROW_LIMIT}`),
    scan(`SELECT window_start, window_seconds, keystroke_interval_mean_ms, keystroke_interval_std_ms, key_dwell_mean_ms,
                 mouse_velocity_mean_px_s, mouse_velocity_std_px_s, scroll_events, scroll_velocity_mean, app_switches,
                 idle_seconds, open_window_count, copy_paste_events
          FROM biometric_samples WHERE user_id = ? AND window_start >= ? AND window_start < ?
          ORDER BY window_start LIMIT ${ROW_LIMIT}`),
    scan(`SELECT occurred_at, event_type, target_user_id, ticket_id, details FROM privilege_events
          WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ? ORDER BY occurred_at LIMIT ${ROW_LIMIT}`),
    scan(`SELECT occurred_at, source_ip, bytes_out FROM network_events
          WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ? ORDER BY occurred_at LIMIT ${ROW_LIMIT}`),
    scan(`SELECT occurred_at, event_type, sensitive_keyword_hits FROM communication_events
          WHERE user_id = ? AND occurred_at >= ? AND occurred_at < ? ORDER BY occurred_at LIMIT ${ROW_LIMIT}`),
    scan(`SELECT started_at, ended_at, source_ip, city, device_id FROM user_sessions
          WHERE user_id = ? AND started_at >= ? AND started_at < ? ORDER BY started_at LIMIT ${ROW_LIMIT}`),
    scan(`SELECT window_start, keys_z, pointer_z FROM biometric_windows
          WHERE user_id = ? AND window_start >= ? AND window_start < ? AND distance_z IS NOT NULL
          ORDER BY window_start LIMIT ${ROW_LIMIT}`),
  ]);

  return { files, transfers, clipboard, endpoints, auth, biometrics, privilege, network, communication, sessions, biometricWindows };
}

// The person's HR timeline and employment details, which live in the CrimGuard tables because
// Red has no HR system of its own.
async function loadSubject(db, userId, date) {
  const [person, hrEvents, leave, projects] = await Promise.all([
    db.query('SELECT employment_type, hire_date, termination_date, is_privileged, created_at FROM users WHERE id = ?', [userId]),
    db.query('SELECT event_type, effective_date, is_negative, recorded_at FROM hr_events WHERE user_id = ? AND effective_date <= ? ORDER BY effective_date DESC LIMIT 200', [userId, date]),
    db.query('SELECT leave_type, starts_on, ends_on, days_requested, balance_before, requested_at, approved FROM leave_periods WHERE user_id = ? ORDER BY starts_on DESC LIMIT 100', [userId]),
    db.query(`SELECT p.starts_on, pm.joined_on FROM project_members pm JOIN projects p ON p.id = pm.project_id
              WHERE pm.user_id = ? AND pm.joined_on <= ? ORDER BY pm.joined_on DESC LIMIT 50`, [userId, date]),
  ]);
  return { person: person.rows[0] || {}, hrEvents: hrEvents.rows, leave: leave.rows, projects: projects.rows };
}

// --- the 100 variables ------------------------------------------------------------

function computeFeatures({ date, window, subject, holidays = [], hours = { start: 9, end: 18 }, knownDevices = [], knownIps = [] }) {
  const before = (rows, at = (r) => r.occurred_at) => rows.filter((row) => dayOf(at(row)) < date);
  const on = (rows, at = (r) => r.occurred_at) => rows.filter((row) => dayOf(at(row)) === date);

  const files = on(window.files);
  const filesBefore = before(window.files);
  const transfers = on(window.transfers);
  const clipboard = on(window.clipboard);
  const endpoints = on(window.endpoints);
  const auth = on(window.auth);
  const privilege = on(window.privilege);
  const communication = on(window.communication);
  const samples = on(window.biometrics, (r) => r.window_start);
  const samplesBefore = before(window.biometrics, (r) => r.window_start);
  const sessions = on(window.sessions, (r) => r.started_at);

  const activity = [...files, ...transfers, ...clipboard, ...endpoints, ...privilege];
  // Signing in counts as using Red, even when nothing follows it. A day of nothing but
  // sign-ins - or nothing but failed ones - is exactly the day worth a snapshot: it is where
  // impossible travel, a replayed token and a password-guessing run all show up.
  const active = activity.length > 0 || sessions.length > 0 || auth.length > 0;
  const f = {};

  // ===== 1. ACCESS & RESOURCE =====
  const touched = files.filter((row) => row.resource_id != null);
  const reads = files.filter((row) => row.action === 'read').length;
  const writes = files.filter((row) => ['write', 'rename', 'permission_change'].includes(row.action)).length;
  const deletes = files.filter((row) => row.action === 'delete').length;
  const searches = files.filter((row) => row.action === 'search');
  const confidential = touched.filter((row) => SENSITIVE.has(row.sensitivity) || isSensitiveUri(row.uri));

  f.files_accessed_count = new Set(touched.map((row) => row.resource_id)).size;
  f.distinct_resource_types_touched = new Set(touched.map((row) => row.resource_type).filter(Boolean)).size;
  f.read_write_delete_ratio = (writes + deletes) / Math.max(reads, 1);
  f.confidential_resource_access_count = confidential.length;

  const seenBefore = new Set(filesBefore.map((row) => row.resource_id).filter((id) => id != null));
  f.first_time_resource_access_flag = touched.some((row) => !seenBefore.has(row.resource_id));

  const repeats = new Map();
  for (const row of confidential) repeats.set(row.resource_id, (repeats.get(row.resource_id) || 0) + 1);
  f.repeated_sensitive_file_access_count = sum([...repeats.values()].map((n) => Math.max(0, n - 1)));

  f.bulk_directory_access_flag = touched.some((row) => (row.files_in_batch || 0) >= BULK_DISTINCT_RESOURCES)
    || touched.some((row, i) => {
      const until = msOf(row.occurred_at) + BULK_WINDOW_MS;
      const inWindow = touched.slice(i).filter((other) => msOf(other.occurred_at) < until);
      return new Set(inWindow.map((other) => other.resource_id)).size >= BULK_DISTINCT_RESOURCES;
    });

  f.unusual_search_query_count = searches.filter((row) => classifyText(row.search_query).keywordHits > 0).length;

  // Out-of-scope access is only visible as a refusal: Red never serves the resource.
  const violations = privilege.filter((row) => row.event_type === 'least_privilege_violation');
  f.out_of_scope_resource_access_count = violations.length;

  const downloadBytes = sum(transfers.filter((row) => row.channel === 'download').map((row) => row.bytes || 0));
  const downloadMb = downloadBytes / MB;
  const priorDownloadMb = dailyTotals(byDay(window.transfers), date,
    (rows) => sum(rows.filter((row) => row.channel === 'download').map((row) => row.bytes || 0)) / MB);
  f.download_volume_vs_baseline = ratioToBaseline(downloadMb, priorDownloadMb, 0.5);

  // ===== 2. TEMPORAL =====
  const times = activity.map((row) => msOf(row.occurred_at)).filter(Number.isFinite).sort((a, b) => a - b);
  const hoursToday = activity.map((row) => hourOf(row.occurred_at));
  const priorHours = dailyTotals(byDay(window.files), date, (rows) => median(rows.map((row) => hourOf(row.occurred_at))))
    .filter((value) => value !== null);

  f.access_time_deviation_from_normal_hours = hoursToday.length && priorHours.length
    ? hourGap(median(hoursToday), median(recent(priorHours))) : null;

  const holiday = holidays.includes(date);
  f.weekend_holiday_access_flag = active ? (isWeekend(date) || holiday) : false;

  // A session that is still open counts up to now, or to the end of the day being scored -
  // otherwise the day someone is still signed in for always looks like zero time.
  const sessionSeconds = (rows) => sum(rows.map((row) => {
    const started = msOf(row.started_at);
    const stillOpen = Math.min(Date.now(), Date.parse(startOf(dayOf(row.started_at))) + 86400000 - 1);
    const end = row.ended_at ? msOf(row.ended_at) : Math.max(started, stillOpen);
    return Math.max(0, (end - started) / 1000);
  }));
  const todaySeconds = sessionSeconds(sessions);
  f.session_duration_vs_baseline = ratioToBaseline(
    todaySeconds, dailyTotals(byDay(window.sessions, (r) => r.started_at), date, sessionSeconds), 60,
  );

  const firstSession = sessions.length ? msOf(sessions[0].started_at) : null;
  const firstSensitive = confidential.length ? msOf(confidential[0].occurred_at) : null;
  f.time_to_first_sensitive_access_sec = firstSession !== null && firstSensitive !== null && firstSensitive >= firstSession
    ? Math.round((firstSensitive - firstSession) / 1000) : null;

  f.after_hours_access_frequency = hoursToday.length
    ? hoursToday.filter((h) => h < hours.start || h >= hours.end || isWeekend(date)).length / hoursToday.length
    : null;

  const priorFirst = dailyTotals(byDay(window.files), date, (rows) => Math.min(...rows.map((row) => hourOf(row.occurred_at))));
  const priorLast = dailyTotals(byDay(window.files), date, (rows) => Math.max(...rows.map((row) => hourOf(row.occurred_at))));
  f.activity_start_end_time_shift = hoursToday.length && priorFirst.length
    ? ((Math.min(...hoursToday) - median(recent(priorFirst))) + (Math.max(...hoursToday) - median(recent(priorLast)))) / 2
    : null;

  f.leave_period_activity_flag = active && subject.leave.some((row) => row.approved && date >= row.starts_on && date <= row.ends_on);

  const activeDays = [...byDay(window.files).keys()].filter((day) => day < date).sort();
  if (!active || activeDays.length < 3) {
    f.unusual_inactivity_gap_flag = active ? false : null;
  } else {
    const gaps = activeDays.slice(1).map((day, i) => (Date.parse(day) - Date.parse(activeDays[i])) / 86400000);
    const since = (Date.parse(date) - Date.parse(activeDays.at(-1))) / 86400000;
    f.unusual_inactivity_gap_flag = since >= 7 && since > 3 * Math.max(median(gaps) ?? 1, 1);
  }

  let busiest = 0;
  for (let i = 0; i < times.length; i++) {
    const until = times[i] + BULK_WINDOW_MS;
    busiest = Math.max(busiest, times.filter((t) => t >= times[i] && t < until).length);
  }
  f.burst_activity_flag = times.length >= BURST_MIN_EVENTS && busiest / times.length >= BURST_SHARE;

  const weekday = new Date(`${date}T00:00:00Z`).getUTCDay();
  const sameWeekday = [...byDay(window.files)]
    .filter(([day]) => day < date && new Date(`${day}T00:00:00Z`).getUTCDay() === weekday)
    .map(([, rows]) => rows.length);
  f.day_of_week_pattern_change_score = sameWeekday.length >= 2
    ? Math.min(5, Math.abs(Math.log((files.length + 1) / ((median(sameWeekday) ?? 0) + 1))))
    : null;

  // ===== 3. DATA MOVEMENT =====
  f.daily_download_volume_mb = downloadMb;
  f.print_job_volume = sum(endpoints.filter((row) => row.event_type === 'print_job')
    .map((row) => Number(row.details?.pages) || 1));
  f.large_clipboard_copy_event_count = clipboard.filter((row) => (row.char_count || 0) >= LARGE_COPY_CHARS).length;

  const exports_ = transfers.filter((row) => row.channel === 'download');
  const renames = files.filter((row) => row.action === 'rename');
  f.file_rename_before_export_count = renames.filter((rename) =>
    exports_.some((exported) => {
      const gap = msOf(exported.occurred_at) - msOf(rename.occurred_at);
      return gap >= 0 && gap <= RENAME_BEFORE_EXPORT_MS;
    })).length;

  // ===== 4. AUTHENTICATION & IDENTITY =====
  const logins = auth.filter((row) => row.event_type === 'login_success');
  f.failed_login_attempt_count = auth.filter((row) => row.event_type === 'login_failure').length;
  f.password_reset_frequency = auth.filter((row) => row.event_type === 'password_reset').length;
  f.session_token_reuse_flag = auth.some((row) => row.event_type === 'session_token_reuse');

  const newDevice = logins.some((row) => row.device_id != null && !knownDevices.includes(row.device_id));
  f.new_device_login_flag = logins.length ? newDevice : false;

  // A network or a country this account has not signed in from before.
  const authBefore = before(window.auth);
  const zonesBefore = new Set(authBefore.map((row) => row.city).filter(Boolean));
  const countriesBefore = new Set(authBefore.map((row) => row.country_code).filter(Boolean));
  const prefixes = logins.map((row) => ipPrefix(row.source_ip)).filter(Boolean);
  f.new_geolocation_login_flag = logins.length
    ? prefixes.some((prefix) => !knownIps.includes(prefix))
      || logins.some((row) => row.city && !zonesBefore.has(row.city))
      || (countriesBefore.size > 0 && logins.some((row) => row.country_code && !countriesBefore.has(row.country_code)))
    : false;

  f.concurrent_session_diff_location_flag = sessions.some((a, i) => sessions.slice(i + 1).some((b) => {
    const aEnd = a.ended_at ? msOf(a.ended_at) : Infinity;
    const overlaps = msOf(b.started_at) < aEnd - CONCURRENT_GAP_MS;
    return overlaps && ipPrefix(a.source_ip) && ipPrefix(b.source_ip) && ipPrefix(a.source_ip) !== ipPrefix(b.source_ip);
  }));

  // ===== 5. DEVICE & NETWORK =====
  f.new_device_fingerprint_flag = f.new_device_login_flag;

  // Every address this account was seen from today, not only the ones it signed in from:
  // the catalog's source for this one is network_events, which carries the address of each
  // request. So turning on a VPN, tethering, or moving networks mid-session shows up here
  // even though no new sign-in happened.
  //
  // This is a flag, and the engine baselines flags on how often they fire over 90 days. An
  // account whose address changes every day builds a rate near 1 and earns nothing from it;
  // one that has sat on the same network for months and suddenly moves is strong evidence.
  // The noisy case calibrates itself away rather than needing a threshold here.
  const addressesToday = [...new Set([
    ...prefixes,
    ...on(window.network).map((row) => ipPrefix(row.source_ip)),
    ...sessions.map((row) => ipPrefix(row.source_ip)),
  ].filter(Boolean))];

  f.unusual_ip_range_flag = addressesToday.length
    ? addressesToday.some((prefix) => !knownIps.includes(prefix))
    : false;

  // Impossible travel: two sign-ins from places too far apart for the time between them.
  // Judged in kilometres per hour, not hours of offset - Paris and Lagos share an offset and
  // are 4,500 km apart, while Lisbon and London are an hour apart and nearly neighbours.
  //
  // Today's sign-ins are compared with each other and with the last one before today, so a
  // jump across midnight is not missed. The network has to have changed too: a VPN moves the
  // address without moving the person, and changing a laptop's region setting moves neither.
  const placed = [...before(window.auth).filter((row) => row.event_type === 'login_success').slice(-5), ...logins]
    .map((row) => ({
      at: msOf(row.occurred_at),
      prefix: ipPrefix(row.source_ip),
      today: dayOf(row.occurred_at) === date,
      location: Number.isFinite(row.latitude) && Number.isFinite(row.longitude)
        ? { latitude: row.latitude, longitude: row.longitude }
        : locate({ timezone: row.city }),
    }))
    .filter((row) => row.location);

  f.travel = null;
  f.impossible_travel_flag = logins.length ? placed.some((a, i) => placed.slice(i + 1).some((b) => {
    if (!b.today) return false; // only score journeys that end today
    if (b.at - a.at > TRAVEL_WINDOW_MS) return false;
    if (a.prefix && b.prefix && a.prefix === b.prefix) return false;

    const journey = travelBetween(a, b);
    if (journey?.impossible) f.travel = journey;
    return Boolean(journey?.impossible);
  })) : false;

  // The browser reports its platform in the fingerprint; the user agent is sent separately.
  // They only disagree when one of the two has been tampered with.
  f.user_agent_inconsistency_flag = logins.some((row) => {
    const ua = String(row.user_agent || '').toLowerCase();
    if (!ua) return false;
    const claims = { windows: /windows/, mac: /mac os|macintosh/, linux: /linux|x11/, android: /android/, ios: /iphone|ipad/ };
    const matched = Object.entries(claims).filter(([, pattern]) => pattern.test(ua)).map(([name]) => name);
    return matched.length > 1 && !(matched.includes('linux') && matched.includes('android'));
  });

  const bytesOut = sum(on(window.network).map((row) => row.bytes_out || 0));
  f.bandwidth_usage_spike = ratioToBaseline(bytesOut / MB,
    dailyTotals(byDay(window.network), date, (rows) => sum(rows.map((row) => row.bytes_out || 0)) / MB), 0.25);

  // ===== 6. BEHAVIORAL BIOMETRICS =====
  const statOf = (rows, field) => mean(rows.map((row) => row[field]).filter((value) => Number.isFinite(value)));
  const dailyStat = (field) => dailyTotals(byDay(window.biometrics, (r) => r.window_start), date, (rows) => statOf(rows, field))
    .filter((value) => value !== null);

  // Against the person's own typing and pointer profile (src/biometrics/) when the page sent
  // judged windows today; otherwise the day's average against earlier days.
  const judged = biometricDeviation(on(window.biometricWindows || [], (r) => r.window_start)
    .map((row) => ({ keysZ: row.keys_z, pointerZ: row.pointer_z })));
  f.keystroke_cadence_deviation = judged.keys
    ?? deviation(statOf(samples, 'keystroke_interval_mean_ms'), dailyStat('keystroke_interval_mean_ms'), 5);
  f.mouse_velocity_deviation = judged.pointer
    ?? deviation(statOf(samples, 'mouse_velocity_mean_px_s'), dailyStat('mouse_velocity_mean_px_s'), 10);

  const scrollDeviation = deviation(statOf(samples, 'scroll_velocity_mean'), dailyStat('scroll_velocity_mean'), 5);
  // Consistency is the opposite of deviation, on a 0-1 scale: 1 is exactly the usual pattern.
  f.scroll_behavior_consistency_score = scrollDeviation === null ? null : 2 ** -Math.abs(scrollDeviation);

  f.app_switch_frequency = samples.length ? sum(samples.map((row) => row.app_switches || 0)) : null;

  const idleShare = (rows) => {
    const seconds = sum(rows.map((row) => row.window_seconds || 0));
    return seconds ? sum(rows.map((row) => row.idle_seconds || 0)) / seconds : null;
  };
  f.idle_time_pattern_score = deviation(samples.length ? idleShare(samples) : null,
    dailyTotals(byDay(window.biometrics, (r) => r.window_start), date, idleShare).filter((v) => v !== null), 0.05);

  f.copy_paste_frequency_volume = clipboard.length;
  f.screenshot_recording_activity_count = endpoints.filter((row) => ['screenshot', 'screen_recording'].includes(row.event_type)).length;
  f.open_app_window_count = samples.length ? Math.max(...samples.map((row) => row.open_window_count || 0)) : null;

  const signature = [f.keystroke_cadence_deviation, f.mouse_velocity_deviation, f.idle_time_pattern_score,
    f.scroll_behavior_consistency_score === null ? null : (1 - f.scroll_behavior_consistency_score) * 3]
    .filter((value) => value !== null && Number.isFinite(value));
  f.digital_signature_deviation_score = signature.length
    ? Math.sqrt(sum(signature.map((value) => value ** 2)) / signature.length) : null;

  // ===== 7. HR & ORGANIZATIONAL CONTEXT =====
  const daysSince = (day) => (day ? (Date.parse(date) - Date.parse(day)) / 86400000 : Infinity);
  const hrWithin = (type, days, negativeOnly = false) => subject.hrEvents.some((row) =>
    row.event_type === type && (!negativeOnly || row.is_negative) && daysSince(row.effective_date) <= days && daysSince(row.effective_date) >= 0);

  f.recent_role_change_flag = hrWithin('role_change', 30);
  f.termination_date_on_file = subject.person.termination_date ?? null;
  f.recent_negative_review_flag = hrWithin('performance_review', 180, true);
  f.recent_disciplinary_action_flag = hrWithin('disciplinary_action', 180);
  f.manager_change_flag = hrWithin('manager_change', 90);
  f.compensation_change_flag = hrWithin('compensation_change', 90);
  f.employment_type = subject.person.employment_type ?? null;

  f.pto_dump_flag = subject.leave.some((row) =>
    row.days_requested >= 5 && row.balance_before > 0 && row.days_requested >= 0.8 * row.balance_before
    && daysSince(String(row.requested_at || row.starts_on).slice(0, 10)) <= 90);

  const hired = subject.person.hire_date || String(subject.person.created_at || '').slice(0, 10) || null;
  f.tenure_months = hired ? Math.max(0, Math.floor(daysSince(hired) / 30.44)) : null;

  f.recent_project_assignment_flag = subject.projects.some((row) => daysSince(row.joined_on) <= 30 && daysSince(row.joined_on) >= 0);

  // ===== 8. COMMUNICATION & COLLABORATION =====
  f.sensitive_keyword_message_count = sum(communication.map((row) => row.sensitive_keyword_hits || 0));
  f.credential_sharing_in_chat_flag = communication.some((row) => row.event_type === 'credential_shared')
    || clipboard.some((row) => (row.detected_patterns || []).length > 0);

  // ===== 9. PRIVILEGE & PERMISSION =====
  const privilegeOf = (type) => privilege.filter((row) => row.event_type === type);
  f.permission_change_count = privilegeOf('permission_change').length;
  f.admin_panel_access_flag = privilegeOf('admin_panel_access').length > 0;
  f.new_account_creation_count = privilegeOf('account_created').length;
  f.audit_log_modification_flag = privilegeOf('audit_log_modified').length > 0;
  f.least_privilege_violation_flag = violations.length > 0;
  f.sensitive_group_membership_change_flag = privilegeOf('sensitive_group_membership_change').length > 0;
  f.no_ticket_new_system_access_flag = privilegeOf('new_system_access_granted').some((row) => row.ticket_id == null);

  // ===== 10. PHYSICAL & ENVIRONMENTAL =====
  f.sensitive_document_print_copy_count = endpoints
    .filter((row) => row.event_type === 'print_job' && row.details?.sensitive === true)
    .reduce((total, row) => total + (Number(row.details?.pages) || 1), 0);

  // A day with nothing on it at all is left empty rather than filled with zeroes, so the
  // baselines are built from days the person actually used Red.
  if (!active) return { active: false, features: {} };

  // Not one of the 100: how far and how fast, kept so the console can say why the flag is set.
  const travel = f.travel;
  delete f.travel;

  for (const [key, value] of Object.entries(f)) {
    if (value === undefined || (typeof value === 'number' && !Number.isFinite(value))) f[key] = null;
  }
  return { active: true, features: f, travel };
}

// --- entry point ------------------------------------------------------------------

// Computes one person's variables for one day. `context` carries what the caller already
// looked up once for every user (holidays, working hours).
async function featuresFor(db, userId, date, context = {}) {
  const from = startOf(addDays(date, -HISTORY_DAYS));
  const to = startOf(addDays(date, 1));
  const [window, subject] = await Promise.all([loadWindow(db, userId, from, to), loadSubject(db, userId, date)]);

  // Devices and addresses seen before today decide what counts as "new". Addresses are
  // gathered from everywhere they appear, so a network that is only ever used mid-session
  // still counts as one this account has used before.
  const past = (rows, at = (row) => row.occurred_at) => rows.filter((row) => dayOf(at(row)) < date);
  const knownDevices = [...new Set(past(window.auth).map((row) => row.device_id).filter((id) => id != null))];
  const knownIps = [...new Set([
    ...past(window.auth).map((row) => ipPrefix(row.source_ip)),
    ...past(window.network).map((row) => ipPrefix(row.source_ip)),
    ...past(window.sessions, (row) => row.started_at).map((row) => ipPrefix(row.source_ip)),
  ].filter(Boolean))];

  return computeFeatures({ date, window, subject, knownDevices, knownIps, ...context });
}

module.exports = {
  featuresFor, computeFeatures, loadWindow, loadSubject,
  HISTORY_DAYS, BASELINE_DAYS, median, mean, stdev, ratioToBaseline, deviation, ipPrefix,
};
