'use strict';

// Downloading a file above your clearance.
//
// A file shared with someone by name opens at any confidentiality (db/files.js), and risk limiting
// deliberately leaves that door alone. Two rules sit on it here, at the point of taking a copy:
//
//   a code, every time   a download of a file above the person's clearance waits for the
//                        verification code. One accepted code is good for one download, soon
//                        after, on this session only - so a copy of a Restricted file is always a
//                        deliberate act by whoever holds the account, never a stray request.
//
//   grabbing it at once  reaching for that file within seconds of being given it is what a
//                        script, or someone waiting for the share to land, looks like. A person
//                        who was sent a file to work on opens it when they get to it. It raises
//                        the score as a live adjustment (security/risk-signals.js explains why an
//                        adjustment rather than an edit), and it is judged on the first attempt,
//                        before the code is asked for, so the time spent typing a code cannot
//                        launder a grab into a slow download.
//
// What counts as "given it": the moment the by-name grant was made, or the moment an admin released
// the file to someone on their notice (security/departure.js), whichever is later.
//
// Clearance here is the effective one, after risk limiting, the same one the departure gate reads:
// an account whose score has cut its reach meets these rules on the files that cut put out of reach.

const RAPID_DOWNLOAD = Object.freeze({
  kind: 'rapid_above_clearance_download',
  // "Within 5 seconds". Grant times are stored to the second, so this is measured in whole seconds.
  windowSeconds: 5,
  delta: 20,
  holdsForMs: 7 * 24 * 60 * 60 * 1000,
});

const DOWNLOAD_MFA = Object.freeze({
  // Long enough to type the code and let the retry arrive, short enough that a code answered and
  // walked away from does not leave a download waiting on the session.
  validForMs: 2 * 60 * 1000,
  // Wrong codes for one file on one session before it stops accepting any.
  maxAttempts: 5,
});

// Their own file is never above them, whatever it is marked.
const aboveClearance = ({ confidentiality, clearance, isOwner = false }) =>
  !isOwner && Number(confidentiality) > Number(clearance);

// SQLite's datetime('now') text ("YYYY-MM-DD HH:MM:SS", UTC) or an ISO string, as epoch ms.
function parseTime(value) {
  if (!value) return null;
  const text = String(value);
  const ms = Date.parse(text.includes('T') ? text : `${text.replace(' ', 'T')}Z`);
  return Number.isFinite(ms) ? ms : null;
}

// Whole seconds from `since` to `now`, compared at the precision the grant was stored with.
function secondsSince(since, now = Date.now()) {
  const then = parseTime(since);
  if (then === null) return null;
  return Math.floor(now / 1000) - Math.floor(then / 1000);
}

// Whether this download attempt is a grab. `accessSince` is when the person was given the file.
function rapidDownload({ accessSince, now = Date.now(), policy = RAPID_DOWNLOAD }) {
  const seconds = secondsSince(accessSince, now);
  return { rapid: seconds !== null && seconds >= 0 && seconds <= policy.windowSeconds, seconds };
}

module.exports = { RAPID_DOWNLOAD, DOWNLOAD_MFA, aboveClearance, parseTime, secondsSince, rapidDownload };
