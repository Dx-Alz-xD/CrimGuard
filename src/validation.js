'use strict';

const { HttpError } = require('./http/errors');
const { checkPassword } = require('./security/password-policy');
const { STATUSES } = require('./db');

// C0/C1 control characters, and the bidirectional overrides that can make a name
// display differently from what it contains (e.g. an email that "reads" as someone else's).
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
const BIDI = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

const cleanText = (value) =>
  typeof value === 'string' ? value.normalize('NFC').replace(CONTROL, '').replace(BIDI, '') : '';

const singleLine = (value) => cleanText(value).replace(/\s+/g, ' ').trim();

// Keeps line breaks, normalises Windows line endings, trims the ends.
const multiLine = (value) => cleanText(value).replace(/\r\n?/g, '\n').replace(/\t/g, ' ').trim();

function normalizeEmail(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  const valid = email.length <= 254
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    && cleanText(email) === email;
  return valid ? email : '';
}

function personName(value) {
  const name = singleLine(value);
  if (!name || name.length > 80) throw new HttpError(400, 'Enter a name (up to 80 characters).');
  return name;
}

function requiredEmail(value) {
  const email = normalizeEmail(value);
  if (!email) throw new HttpError(400, 'Enter a valid email address.');
  return email;
}

function newPassword(value, context) {
  const problem = checkPassword(value, context);
  if (problem) throw new HttpError(400, problem);
  return value;
}

// Validates a create (no `current`) or a partial update merged over `current`.
function projectFields(body, current = { name: '', description: '', status: 'planning' }) {
  const name = Object.hasOwn(body, 'name') ? singleLine(body.name) : current.name;
  const description = Object.hasOwn(body, 'description') ? multiLine(body.description) : current.description;
  const status = Object.hasOwn(body, 'status') ? body.status : current.status;

  if (!name) throw new HttpError(400, 'Project name is required.');
  if (name.length > 120) throw new HttpError(400, 'Project name must be 120 characters or fewer.');
  if (description.length > 2000) throw new HttpError(400, 'Description must be 2000 characters or fewer.');
  if (!STATUSES.includes(status)) throw new HttpError(400, `Status must be one of: ${STATUSES.join(', ')}.`);
  return { name, description, status };
}

function profileFields(body, current) {
  const pick = (key, clean, fallback) => (Object.hasOwn(body, key) ? clean(body[key]) : fallback);
  const fields = {
    name: Object.hasOwn(body, 'name') ? personName(body.name) : current.name,
    jobTitle: pick('jobTitle', singleLine, current.job_title),
    organization: pick('organization', singleLine, current.organization),
    bio: pick('bio', multiLine, current.bio),
  };
  if (fields.jobTitle.length > 80) throw new HttpError(400, 'Job title must be 80 characters or fewer.');
  if (fields.organization.length > 80) throw new HttpError(400, 'Team or organization must be 80 characters or fewer.');
  if (fields.bio.length > 500) throw new HttpError(400, 'About you must be 500 characters or fewer.');
  return fields;
}

module.exports = { singleLine, multiLine, normalizeEmail, personName, requiredEmail, newPassword, projectFields, profileFields };
