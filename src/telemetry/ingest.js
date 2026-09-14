'use strict';

// Validates one batch from public/static/telemetry.js and turns it into raw events.
//
// A page can say anything, so this endpoint only accepts the signals the server has no other
// way of seeing: pointer and typing rhythm, scrolling, idle time, focus changes, clipboard
// size, printing, screen capture, and the browser's own description of itself. Everything the
// server can observe for itself - which resources were opened, what was searched for, who
// signed in, who changed a role, how many bytes were sent - is recorded in the route handlers
// instead, where it cannot be forged. Batches are capped so one page cannot flood the tables.

const { HttpError } = require('../http/errors');

const MAX_SAMPLES = 24;
const MAX_EVENTS = 200;
const MAX_WINDOW_SECONDS = 3600;
const MAX_CHARS = 50_000_000;
// A batch older than this is dropped: a page left open overnight replaying stale windows would
// otherwise land them on the wrong day.
const MAX_AGE_MS = 6 * 60 * 60 * 1000;
const MAX_SKEW_MS = 5 * 60 * 1000;

const ENDPOINT_EVENTS = {
  print: 'print_job',
  screenshot: 'screenshot',
  screen_recording: 'screen_recording',
  app_switch: 'app_switch',
};
const CLIPBOARD_EVENTS = new Set(['copy', 'cut', 'paste']);

// Kinds of secret the collector reports having matched. The text itself is never sent.
const PATTERNS = new Set(['api_key', 'password', 'private_key', 'token', 'credit_card', 'ssn', 'email_list', 'source_code']);

const num = (value, min, max) => {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(Math.max(n, min), max) : null;
};
const nonNegative = (value, max) => num(value, 0, max);

// Client clocks drift and can be set deliberately. Timestamps are clamped into the window
// between the batch arriving and MAX_AGE_MS before it.
function timestamp(value, now) {
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return new Date(now).toISOString();
  return new Date(Math.min(Math.max(ms, now - MAX_AGE_MS), now + MAX_SKEW_MS)).toISOString();
}

function parseDevice(device = {}) {
  if (device === null || typeof device !== 'object') return {};
  const str = (value, max) => (typeof value === 'string' ? value.slice(0, max) : null);
  return {
    fingerprint: str(device.fingerprint, 128),
    platform: str(device.platform, 64),
    timezone: str(device.timezone, 64),
    screen: str(device.screen, 32),
    language: str(device.language, 32),
    // Rounded off: the exact core count and memory size would narrow a browser down further
    // than this needs to, and the fingerprint already covers identity.
    cores: nonNegative(device.cores, 256),
  };
}

function parseSample(raw, now) {
  if (!raw || typeof raw !== 'object') return null;
  // A window has to say how long it was. Clamping a missing or zero length up to a second
  // would invent a sample rather than drop one.
  if (!Number.isFinite(Number(raw.seconds)) || Number(raw.seconds) < 1) return null;
  const windowSeconds = num(raw.seconds, 1, MAX_WINDOW_SECONDS);
  return {
    windowStart: timestamp(raw.at, now),
    windowSeconds,
    keystrokeIntervalMeanMs: nonNegative(raw.keyIntervalMean, 600_000),
    keystrokeIntervalStdMs: nonNegative(raw.keyIntervalStd, 600_000),
    keyDwellMeanMs: nonNegative(raw.keyDwellMean, 60_000),
    mouseVelocityMeanPxS: nonNegative(raw.mouseVelocityMean, 100_000),
    mouseVelocityStdPxS: nonNegative(raw.mouseVelocityStd, 100_000),
    scrollEvents: nonNegative(raw.scrollEvents, 100_000),
    scrollVelocityMean: nonNegative(raw.scrollVelocityMean, 1_000_000),
    appSwitches: nonNegative(raw.appSwitches, 10_000),
    idleSeconds: nonNegative(raw.idleSeconds, MAX_WINDOW_SECONDS),
    openWindowCount: nonNegative(raw.windows, 1000),
    copyPasteEvents: nonNegative(raw.copyPaste, 10_000),
  };
}

function parseEvent(raw, now) {
  if (!raw || typeof raw !== 'object' || typeof raw.type !== 'string') return null;
  const at = timestamp(raw.at, now);

  if (CLIPBOARD_EVENTS.has(raw.type)) {
    return {
      table: 'clipboard',
      at,
      action: raw.type,
      charCount: nonNegative(raw.chars, MAX_CHARS) ?? 0,
      patterns: Array.isArray(raw.patterns) ? [...new Set(raw.patterns.filter((p) => PATTERNS.has(p)))].slice(0, 8) : [],
      // 'red' for a copy out of a Red page, 'external' for a paste in from somewhere else.
      source: raw.type === 'paste' ? 'external' : 'red',
      destination: raw.type === 'paste' ? 'red' : 'external',
    };
  }

  const endpointType = ENDPOINT_EVENTS[raw.type];
  if (endpointType) {
    return {
      table: 'endpoint',
      at,
      eventType: endpointType,
      pages: nonNegative(raw.pages, 10_000),
      sensitiveOnScreen: raw.sensitive === true,
    };
  }
  return null;
}

// Throws HttpError for a body that isn't a batch at all; silently drops individual entries
// that don't parse, so one bad event never costs the whole batch.
function parseBatch(body, { now = Date.now() } = {}) {
  if (!body || typeof body !== 'object') throw new HttpError(400, 'Expected a telemetry batch.');
  const samples = Array.isArray(body.samples) ? body.samples : [];
  const events = Array.isArray(body.events) ? body.events : [];
  if (samples.length > MAX_SAMPLES || events.length > MAX_EVENTS) {
    throw new HttpError(413, 'Telemetry batch is too large.');
  }

  return {
    device: parseDevice(body.device),
    windows: nonNegative(body.windows, 1000),
    samples: samples.map((sample) => parseSample(sample, now)).filter(Boolean),
    events: events.map((event) => parseEvent(event, now)).filter(Boolean),
  };
}

module.exports = { parseBatch, MAX_SAMPLES, MAX_EVENTS, PATTERNS };
