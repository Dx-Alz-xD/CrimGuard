'use strict';

// The dictionaries behind unusual_search_query_count, sensitive_keyword_message_count and
// credential_sharing_in_chat_flag.
//
// Matching happens where the text already is - in the search box handler, or on a project
// description as it is saved - and only the names of the categories matched are ever stored.
// The text itself is never copied into the risk database.

// Terms that are unremarkable in isolation but tell you what someone was looking for.
const SENSITIVE_TERMS = [
  'salary', 'salaries', 'payroll', 'compensation', 'bonus', 'severance',
  'password', 'passwords', 'passphrase', 'credential', 'credentials', 'secret', 'secrets',
  'api key', 'apikey', 'private key', 'token', 'ssh key', '.pem', '.env',
  'ssn', 'social security', 'passport', 'national insurance',
  'confidential', 'restricted', 'classified', 'nda', 'non-disclosure',
  'acquisition', 'merger', 'layoff', 'layoffs', 'redundancy', 'termination list',
  'customer list', 'client list', 'contact list', 'pricing model', 'source code',
  'roadmap', 'patent', 'formula', 'trade secret',
];

// Secret shapes. Deliberately conservative: a false positive here becomes a risk signal
// against a real person, so each pattern wants real structure, not just a keyword.
const SECRET_PATTERNS = [
  ['private_key', /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/],
  ['api_key', /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/],
  ['api_key', /\bAKIA[0-9A-Z]{16}\b/],
  ['api_key', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['token', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ['password', /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*\S{6,}/i],
  ['credit_card', /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{2,4}\b/],
  ['ssn', /\b\d{3}-\d{2}-\d{4}\b/],
];

// An email address list, which is what a contact export looks like when it is pasted.
const EMAIL_LIST = /[^\s@]+@[^\s@]+\.[^\s@]+/g;
const EMAIL_LIST_THRESHOLD = 5;

// How many sensitive terms `text` contains. Counts each distinct term once, so repeating one
// word does not build a score on its own.
function sensitiveTermHits(text) {
  if (typeof text !== 'string' || !text) return 0;
  const haystack = text.toLowerCase();
  let hits = 0;
  for (const term of SENSITIVE_TERMS) {
    // Terms with a space or a dot are matched as written; single words need a word boundary,
    // so "token" does not fire on "tokenizer".
    const matched = /[ .]/.test(term)
      ? haystack.includes(term)
      : new RegExp(`\\b${term}\\b`).test(haystack);
    if (matched) hits += 1;
  }
  return hits;
}

// The names of the secret categories `text` matches, e.g. ['api_key', 'password'].
function secretPatterns(text) {
  if (typeof text !== 'string' || !text) return [];
  const found = new Set();
  for (const [name, pattern] of SECRET_PATTERNS) {
    if (pattern.test(text)) found.add(name);
  }
  if ((text.match(EMAIL_LIST) || []).length >= EMAIL_LIST_THRESHOLD) found.add('email_list');
  return [...found];
}

// One pass over a piece of text a person wrote or copied.
function classifyText(text) {
  const patterns = secretPatterns(text);
  const keywordHits = sensitiveTermHits(text);
  return {
    keywordHits,
    patterns,
    hasSecret: patterns.length > 0,
    // Drives clipboard_events.content_classification.
    sensitivity: patterns.length ? 'restricted' : keywordHits >= 2 ? 'confidential' : keywordHits ? 'internal' : null,
  };
}

module.exports = { SENSITIVE_TERMS, sensitiveTermHits, secretPatterns, classifyText };
