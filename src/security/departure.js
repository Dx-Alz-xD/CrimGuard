'use strict';

// Departure gating: while someone is working their notice, a file shared with them *by name* that
// sits above their clearance stops being self-service and needs an admin to release it.
//
// Why by-name grants and nothing else. Red already decides the wide questions with clearance: an
// admin's reach over everything at or below their level, and a file shared with a whole role. Risk
// limiting cuts that clearance when a score climbs (security/limits.js). A grant made to one person
// by name is deliberately outside all of it — it opens at any confidentiality, and limiting leaves
// it alone, because narrowing someone's reach should not lock them out of the file a colleague
// handed them to work on.
//
// That is the right default right up until someone is leaving. CERT's insider-threat work (which
// the risk engine already leans on for the HR amplifier) puts theft of intellectual property in the
// weeks around departure, and a by-name grant above clearance is the one door risk limiting does
// not close. So inside the notice window, and only inside it, that door gets a lock with an admin
// holding the key.
//
// What this is not. It does not hide the file, because someone has to be able to ask for it: it is
// listed exactly as before and refused at the point of download, with a request to make. It does
// not touch a file the person owns, nor one their clearance already covers — the point is to put a
// decision in front of the small set of files that are both above their level and individually
// handed to them, not to stop them working.

// "A week or two out." A notice period is usually longer than this; the gate is for the end of it.
const NOTICE_WINDOW_DAYS = 14;

// How long an approval lasts. Long enough to finish the piece of work it was asked for, short
// enough that it expires before the leaving date it was granted against.
const APPROVAL_DAYS = 7;

const DAY_MS = 24 * 60 * 60 * 1000;

const startOfDay = (ms) => {
  const d = new Date(ms);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
};

// Whole days from today until `date` (an ISO yyyy-mm-dd). Negative once the date has passed.
// null when there is no date to measure, which is the ordinary case for almost every account.
function daysUntil(date, now = Date.now()) {
  if (!date) return null;
  const then = Date.parse(`${String(date).slice(0, 10)}T00:00:00Z`);
  if (!Number.isFinite(then)) return null;
  return Math.round((then - startOfDay(now)) / DAY_MS);
}

// Inside the window, or past the leaving date while the account is still open. A date that has come
// and gone without the account being closed is not a reason to relax: it is a reason not to.
function isDeparting(terminationDate, now = Date.now(), windowDays = NOTICE_WINDOW_DAYS) {
  const days = daysUntil(terminationDate, now);
  return days !== null && days <= windowDays;
}

// The one decision, for one person and one file they can already see.
//
//   owner        their own file: never gated
//   clearance    their effective clearance, after risk limiting
//   byName       the grant they reach this file through is an individual one
//   approvedUntil an admin's live approval for this file, if any (ISO timestamp)
//
// Returns { gated, reason, daysLeft }. `gated: false` is the answer for almost every request.
function gateFor({
  terminationDate,
  confidentiality,
  clearance,
  byName,
  isOwner = false,
  approvedUntil = null,
  now = Date.now(),
  windowDays = NOTICE_WINDOW_DAYS,
} = {}) {
  const daysLeft = daysUntil(terminationDate, now);
  if (isOwner) return { gated: false, reason: 'owner', daysLeft };
  if (!isDeparting(terminationDate, now, windowDays)) return { gated: false, reason: 'not_departing', daysLeft };
  // Their clearance covers it, so this is not a by-name decision at all.
  if (Number(confidentiality) <= Number(clearance)) return { gated: false, reason: 'within_clearance', daysLeft };
  if (!byName) return { gated: false, reason: 'not_individually_shared', daysLeft };
  if (approvedUntil && Date.parse(approvedUntil) > now) return { gated: false, reason: 'approved', daysLeft };
  return { gated: true, reason: approvedUntil ? 'approval_expired' : 'needs_approval', daysLeft };
}

// When an approval granted now runs out.
const approvalExpiry = (now = Date.now(), days = APPROVAL_DAYS) => new Date(now + days * DAY_MS).toISOString();

// One line for the admin queue and for the person being refused.
function describe({ daysLeft, confidentiality, clearance }) {
  const when = daysLeft === null ? 'leaving'
    : daysLeft < 0 ? `past their leaving date by ${Math.abs(daysLeft)} day${Math.abs(daysLeft) === 1 ? '' : 's'}`
      : daysLeft === 0 ? 'leaving today'
        : `leaving in ${daysLeft} day${daysLeft === 1 ? '' : 's'}`;
  return `Shared with them by name at level ${confidentiality}, above their clearance of ${clearance}, and ${when}.`;
}

module.exports = { NOTICE_WINDOW_DAYS, APPROVAL_DAYS, daysUntil, isDeparting, gateFor, approvalExpiry, describe };
