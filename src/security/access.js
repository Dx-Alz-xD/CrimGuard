'use strict';

// Who may do what, in one place.
//
// Roles and files share a 1-5 scale:
//   clearance        on a role: the most confidential file its members can be trusted with
//   confidentiality  on a file: how sensitive it is
//
// Seeing a file is decided in SQL, because lists have to be filtered in the query. That rule is
// built from these constants in db/files.js (visibleTo) and written nowhere else. Everything that
// isn't a list, such as handing out roles or changing who can see a file, is decided below.

const BUILT_IN_ROLES = Object.freeze(['intern', 'employee', 'admin', 'ceo']);

// The roles that use the admin console and the CrimGuard dashboard.
const PRIVILEGED_ROLES = Object.freeze(['admin', 'ceo']);

// What public sign-up creates. Anything more is given by an admin or the CEO.
const SIGNUP_ROLE = 'intern';

const CONFIDENTIALITY = Object.freeze({ 1: 'Open', 2: 'Internal', 3: 'Confidential', 4: 'Restricted', 5: 'Secret' });
const DEFAULT_CONFIDENTIALITY = 2;
const MIN_LEVEL = 1;
const MAX_LEVEL = 5;

const isPrivileged = (role) => PRIVILEGED_ROLES.includes(role);
const isCeo = (role) => role === 'ceo';
const isLevel = (value) => Number.isInteger(value) && value >= MIN_LEVEL && value <= MAX_LEVEL;

// Acting on an account, or handing out a role, takes at least that role's clearance. Admins (4) can
// manage interns, employees and each other; only the CEO (5) reaches a CEO or a clearance-5 role.
const outranks = (actor, clearance) => Number(actor.clearance) >= Number(clearance);

// Changing a file's confidentiality or who it is shared with: admins and the CEO, and only for files
// at or below their own clearance, so an admin can neither open nor unlock a Secret file.
const canManageFileAccess = (actor, file) => isPrivileged(actor.role) && outranks(actor, file.confidentiality);

module.exports = {
  BUILT_IN_ROLES,
  PRIVILEGED_ROLES,
  SIGNUP_ROLE,
  CONFIDENTIALITY,
  DEFAULT_CONFIDENTIALITY,
  MIN_LEVEL,
  MAX_LEVEL,
  isPrivileged,
  isCeo,
  isLevel,
  outranks,
  canManageFileAccess,
};
