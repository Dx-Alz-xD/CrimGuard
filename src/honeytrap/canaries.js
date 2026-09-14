'use strict';

// Canary material: fake secrets that look exactly like real ones and exist nowhere but in one
// decoy planted for one person. None of them work anywhere. Seeing one again - copied, pasted
// into a message, sent to an API - can only mean it left that decoy.
//
// Each planting gets freshly generated values, so a canary also says *whose* decoy it came
// from. What gets matched is a SHA-256 fingerprint; the browser only ever sends fingerprints,
// never the text it found them in (see public/static/shared-files.js).
//
// The formats deliberately match the secret patterns in src/telemetry/patterns.js, so a pasted
// canary also lights up the ordinary credential-sharing signals.

const crypto = require('node:crypto');

const UPPER_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const B64ISH = `${ALNUM}/+`;
const DIGITS = '0123456789';

// Unbiased characters from an alphabet. `random(n)` returns n random bytes.
function randomString(alphabet, length, random = crypto.randomBytes) {
  const limit = 256 - (256 % alphabet.length);
  let out = '';
  while (out.length < length) {
    for (const byte of random(length * 2)) {
      if (byte < limit) out += alphabet[byte % alphabet.length];
      if (out.length === length) break;
    }
  }
  return out;
}

const fingerprint = (value) => crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');

// What each kind of canary looks like, and which of its values count as the canary. `values`
// lists every string worth recognising on its own: someone may copy only the password out of
// a connection string, or only the secret half of a key pair.
const KINDS = {
  aws_access_key(r, context) {
    const id = `AKIA${randomString(UPPER_B32, 16, r)}`;
    const secret = randomString(B64ISH, 40, r);
    return {
      tokenType: 'fake_api_key',
      fileName: 'credentials.env',
      values: [id, secret],
      body: [
        `# ${context.service} - production. Rotated quarterly; ask platform before changing.`,
        `AWS_ACCESS_KEY_ID=${id}`,
        `AWS_SECRET_ACCESS_KEY=${secret}`,
        `AWS_REGION=${context.region}`,
        `S3_BUCKET=${context.slug}-prod-exports`,
      ].join('\n'),
    };
  },
  stripe_live_key(r, context) {
    const secret = `sk_live_${randomString(ALNUM, 32, r)}`;
    const webhook = `whsec_${randomString(ALNUM, 32, r)}`;
    return {
      tokenType: 'fake_api_key',
      fileName: 'billing.env',
      values: [secret, webhook],
      body: [
        `# ${context.service} - live payments. Do not use in staging.`,
        `STRIPE_SECRET_KEY=${secret}`,
        `STRIPE_WEBHOOK_SECRET=${webhook}`,
      ].join('\n'),
    };
  },
  github_token(r, context) {
    const token = `ghp_${randomString(ALNUM, 36, r)}`;
    return {
      tokenType: 'fake_api_key',
      fileName: 'deploy-token.txt',
      values: [token],
      body: [
        `Org-wide deploy token for ${context.slug} CI (repo, workflow, read:packages).`,
        `Owner: platform team. Expires in 90 days.`,
        '',
        token,
      ].join('\n'),
    };
  },
  slack_bot_token(r, context) {
    const token = `xoxb-${randomString(DIGITS, 12, r)}-${randomString(DIGITS, 13, r)}-${randomString(ALNUM, 24, r)}`;
    return {
      tokenType: 'fake_api_key',
      fileName: 'slack-integration.env',
      values: [token],
      body: [`# Bot for #exec-updates (${context.orgName})`, `SLACK_BOT_TOKEN=${token}`].join('\n'),
    };
  },
  database_url(r, context) {
    const user = `svc_${context.slug.replace(/-/g, '_')}_rw`;
    const password = randomString(ALNUM, 24, r);
    const host = `db-prod-${randomString(DIGITS, 2, r)}.internal`;
    const url = `postgres://${user}:${password}@${host}:5432/${context.database}`;
    return {
      tokenType: 'fake_credential',
      fileName: 'reporting-db.txt',
      values: [url, password],
      body: [
        `Reporting database - read/write service account (${context.orgName}).`,
        `Used by the nightly exports; do not share outside the data team.`,
        '',
        `DATABASE_URL=${url}`,
      ].join('\n'),
    };
  },
  service_account(r, context) {
    const user = `breakglass-admin@${context.slug}.internal`;
    const password = randomString(`${ALNUM}!#%*`, 22, r);
    const recovery = randomString(UPPER_B32, 26, r);
    return {
      tokenType: 'fake_credential',
      fileName: 'break-glass.txt',
      values: [password, recovery],
      body: [
        `Break-glass administrator for ${context.orgName}. Use only during an outage; every use is reviewed.`,
        '',
        `username: ${user}`,
        `password: ${password}`,
        `recovery code: ${recovery}`,
      ].join('\n'),
    };
  },
  document_link(r, context) {
    const token = randomString(ALNUM, 26, r);
    const url = `https://files.${context.slug}.internal/s/${token}`;
    return {
      tokenType: 'canary_document',
      fileName: `${context.documentName}.xlsx`,
      values: [url, token],
      body: [
        `${context.documentTitle}`,
        `Shared link (internal only): ${url}`,
        `Last updated by ${context.updatedBy}. Restricted - do not forward.`,
      ].join('\n'),
    };
  },
};

function generateCanary(kind, context, { random = crypto.randomBytes } = {}) {
  const make = KINDS[kind];
  if (!make) throw new Error(`Unknown canary kind: ${kind}`);
  const material = make(random, context);
  return { kind, ...material, fingerprints: material.values.map(fingerprint) };
}

// Strings in arbitrary text that could be one of our canaries. The same expressions run in the
// browser; test/honeytrap.test.js checks the two copies stay identical.
const CANDIDATE_PATTERNS = [
  /\bAKIA[A-Z2-7]{16}\b/g,
  /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/g,
  /\b(?:sk_live|whsec)_[A-Za-z0-9]{32}\b/g,
  /\bghp_[A-Za-z0-9]{36}\b/g,
  /\bxoxb-\d{12}-\d{13}-[A-Za-z0-9]{24}\b/g,
  /\bpostgres:\/\/[^\s:@/]+:[A-Za-z0-9]{24}@[^\s/:]+:\d+\/[A-Za-z0-9_]+/g,
  // Bare passwords, recovery codes and link tokens: they are copied on their own as often as
  // inside the line they came from.
  /(?<![A-Za-z0-9])[A-Za-z0-9]{24}(?![A-Za-z0-9])/g,
  /(?<![A-Za-z0-9!#%*])[A-Za-z0-9!#%*]{22}(?![A-Za-z0-9!#%*])/g,
  /(?<![A-Za-z0-9])[A-Za-z0-9]{26}(?![A-Za-z0-9])/g,
  /https:\/\/files\.[a-z0-9-]+\.internal\/s\/[A-Za-z0-9]{26}/g,
];

const MAX_CANDIDATES = 200;

function extractCandidates(text) {
  if (typeof text !== 'string' || text.length < 20) return [];
  const found = new Set();
  for (const pattern of CANDIDATE_PATTERNS) {
    for (const match of text.matchAll(pattern)) {
      found.add(match[0]);
      if (found.size >= MAX_CANDIDATES) return [...found];
    }
  }
  return [...found];
}

const isFingerprint = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

module.exports = { KINDS, generateCanary, extractCandidates, fingerprint, isFingerprint, CANDIDATE_PATTERNS, randomString };
