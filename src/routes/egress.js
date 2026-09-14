'use strict';

// Where the half of shadow-AI detection that Red cannot see for itself arrives.
//
//   POST /api/telemetry/egress            one or more egress observations
//   GET  /api/me/egress                   what was reported about you, and what it was worth
//   GET  /api/admin/egress                the shadow-AI feed, for admins and the CEO
//
// Two kinds of caller, and they are trusted differently:
//
//   a signed-in session   reports only about itself. The account comes from the cookie, never the
//                         body, exactly as /api/telemetry already works, so a page cannot describe
//                         anyone else. This is what a first-party extension or the page itself uses.
//   an agent key          RED_EGRESS_KEY, for something running outside the browser - an EDR agent,
//                         a managed-browser extension's backend, a DLP or forward proxy. It may
//                         name any subject by email, because that is the whole point of it: it
//                         watches the endpoint, not the tab. Without the key set, this door does
//                         not exist at all.
//
// Content is never accepted. A reporter sends how much, where to, and which secret-shaped
// *categories* matched - never the text. Red has no more business holding the body of a paste than
// the browser collector does (public/static/telemetry.js keeps the same line).

const crypto = require('node:crypto');
const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson } = require('../http/response');
const { assess, burstsIn, CATEGORIES } = require('../security/genai');

const MAX_BATCH = 50;
const MAX_PATTERNS = 8;
// Channels a reporter can name. `clipboard` is a paste, `upload` a file, `api` a scripted call.
const CHANNELS = ['clipboard', 'upload', 'api', 'extension'];

const str = (value, max) => (typeof value === 'string' ? value.trim().slice(0, max) : null);
const num = (value, max) => {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? Math.min(n, max) : 0;
};

function registerEgressRoutes(router, { stores, sessions, telemetry, crimguard, ai = null, env = process.env }) {
  const agentKey = env.RED_EGRESS_KEY || '';

  // Constant-time, and only when a key is configured at all.
  function agentAuthorised(req) {
    const given = req.headers['x-red-agent-key'];
    if (!agentKey || typeof given !== 'string') return false;
    const a = Buffer.from(given);
    const b = Buffer.from(agentKey);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  // The organisation's own domain list, which lets a sanctioned enterprise tenant stop counting.
  async function knownDomains() {
    if (!crimguard) return [];
    try {
      const { rows } = await crimguard.query('SELECT domain, app_name, category, is_sanctioned FROM external_domains');
      return rows;
    } catch {
      return [];
    }
  }

  function subjectFor(req, body) {
    const user = sessions.current(req);
    if (user) return { user, self: true };
    if (!agentAuthorised(req)) throw new HttpError(401, 'Sign in, or present an agent key.');
    const email = String(body.email || '').trim().toLowerCase();
    const found = email ? stores.users.findByEmail(email) : null;
    if (!found) throw new HttpError(404, 'No account with that address.');
    return { user: found, self: false };
  }

  // One observation, cleaned. `document` names a file in Red when the reporter could tell - which
  // is what turns "something left the endpoint" into "this document went into that model".
  function clean(raw) {
    const channel = CHANNELS.includes(raw.channel) ? raw.channel : 'clipboard';
    const doc = raw.document && typeof raw.document === 'object' ? raw.document : null;
    return {
      channel,
      destination: str(raw.destination, 200),
      extensionId: str(raw.extensionId, 64),
      chars: num(raw.chars, 50_000_000),
      bytes: num(raw.bytes, 50_000_000_000),
      occurredAt: str(raw.occurredAt, 40) || new Date().toISOString(),
      patterns: Array.isArray(raw.patterns)
        ? raw.patterns.filter((p) => typeof p === 'string').slice(0, MAX_PATTERNS).map((p) => p.slice(0, 40))
        : [],
      fileId: Number.isInteger(raw.fileId) ? raw.fileId : null,
      document: doc ? { name: str(doc.name, 255), project: str(doc.project, 255) } : null,
    };
  }

  router.post('/api/telemetry/egress', async ({ req, res, client }) => {
    const body = await readJson(req);
    const { user, self } = subjectFor(req, body);
    const items = (Array.isArray(body.events) ? body.events : [body]).slice(0, MAX_BATCH).map(clean);
    const known = await knownDomains();

    const results = [];
    for (const item of items) {
      // A file id lets Red fill in the document itself, so a reporter that only saw a filename
      // still gets the confidentiality right - and cannot invent one it was never given.
      let sensitivity = null;
      let document = item.document;
      if (item.fileId) {
        const file = stores.files.visible(item.fileId, user.id);
        if (file) {
          sensitivity = file.confidentiality;
          document = { name: file.name, project: file.project_name };
        }
      }

      const verdict = assess({ ...item, sensitivity, document, known });
      results.push({ ...verdict, channel: item.channel, chars: item.chars, bytes: item.bytes, occurredAt: item.occurredAt, document });

      // Recorded as what it is: a clipboard egress is a clipboard event, a file leaving is a
      // transfer. Both already carry a destination column; nothing new had to be invented.
      await telemetry.onEgress({
        user,
        client,
        tokenHash: self ? req.sessionTokenHash : null,
        channel: item.channel,
        destination: verdict.app || verdict.host || item.destination,
        category: verdict.category,
        chars: item.chars,
        bytes: item.bytes,
        occurredAt: item.occurredAt,
        patterns: item.patterns,
        sensitivity,
        fileName: document?.name ?? null,
      });

      // A document from Red, into an unsanctioned model, is the claim this feature exists to make.
      if (verdict.shadowAi && verdict.severity >= 4) {
        stores.audit.record('security.shadow_ai_egress', {
          actor: user, target: user, ...client,
          details: {
            destination: verdict.app || verdict.host,
            channel: item.channel,
            chars: item.chars,
            level: verdict.level,
            document: document?.name ?? null,
            patterns: item.patterns,
          },
        });
      }
    }

    sendJson(res, 202, { accepted: results.length, results });
  });

  // Everyone can read what was reported about them, for the same reason everyone can read their
  // own risk score: an assessment somebody is not allowed to see is worse than one they are.
  router.get('/api/me/egress', async ({ req, res }) => {
    const user = sessions.requireUser(req);
    const events = await telemetry.egressFor(user.id);
    sendJson(res, 200, { events, bursts: burstsIn(events) });
  });

  // What today's traffic out amounts to, in a paragraph. Counts by destination category go to the
  // model; the people and the documents do not (security/ai-analyst.js).
  router.get('/api/admin/egress/triage', async ({ req, res }) => {
    sessions.requireAdmin(req);
    if (!ai?.enabled()) {
      return sendJson(res, 200, { available: false, reason: 'Set GROQ_API_KEY to turn on written triage.' });
    }
    const events = await telemetry.egressFeed({ limit: 200 });
    const text = await ai.triageEgress(events);
    sendJson(res, 200, { available: Boolean(text), model: ai.model, text, considered: events.length });
  });

  router.get('/api/admin/egress', async ({ req, res, url }) => {
    sessions.requireAdmin(req);
    const onlyShadow = url.searchParams.get('shadow') === '1';
    const events = await telemetry.egressFeed({ limit: 200 });
    const shown = onlyShadow ? events.filter((event) => event.category === CATEGORIES.GENAI) : events;
    sendJson(res, 200, {
      events: shown,
      shadowAi: events.filter((event) => event.category === CATEGORIES.GENAI).length,
      reporting: Boolean(agentKey),
    });
  });
}

module.exports = { registerEgressRoutes, CHANNELS };
