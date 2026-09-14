'use strict';

// Builds everything a request can reach - stores, sessions, telemetry, protection and the
// outside services - and wires the hooks between them. src/app.js turns this into an HTTP
// server; tests and scripts can build it without one.

const { DEFAULT_MAX_FILE_BYTES, RATE_LIMITS, SESSION_POLICY } = require('./config');
const { createStores } = require('./db');
const { createPasswordHasher } = require('./security/passwords');
const { createSessionManager } = require('./security/sessions');
const { createThrottle } = require('./security/throttle');
const { createTelemetry } = require('./telemetry');
const { createProtection } = require('./protection');
const { createReputationService } = require('./security/email-reputation');
const { createProofOfWork } = require('./security/proof-of-work');
const { createAiAnalyst } = require('./security/ai-analyst');
const { ignoreDeletedAccount } = require('./db/errors');

function createServices({
  db,
  pepper,
  crimguard = null,
  secureCookies = false,
  rateLimits = RATE_LIMITS,
  sessionPolicy = SESSION_POLICY,
  now = Date.now,
  maxFileBytes = DEFAULT_MAX_FILE_BYTES,
  protectionOptions = {},
  reputation = null,
  proofOfWork = null,
  ai = null,
  env = process.env,
}) {
  const stores = createStores(db);
  const passwords = createPasswordHasher({ pepper });
  const throttle = createThrottle(db, { now });
  const sessions = createSessionManager({ sessions: stores.sessions, policy: sessionPolicy, secureCookies, now });

  // Identity throttle, biometrics and honeytrapping (src/protection/). Like telemetry, each part
  // is a no-op without the risk database.
  const protection = createProtection({ crimguard, stores, sessions, now, ...protectionOptions });

  // Behavioural telemetry into the CrimGuard risk database. Without that database this is a
  // no-op object, so every route behaves the same whether or not it is connected.
  // Two things hang off every score, and both go through this one hook. The website keeps its
  // own copy in red.db, because that is where the SQL that decides who can see which file can
  // reach it; then the response layer acts on the new score - step-up, freeze, a fresh decoy.
  const telemetry = createTelemetry(crimguard, {
    onScored: async (scored) => {
      const { redUserId, score, level, scenario, date } = scored;
      // A CrimGuard person with no Red account behind them is scored but has nothing to write back to.
      if (redUserId) {
        ignoreDeletedAccount(() => stores.risk.setState(redUserId, { score, level, scenario, scoredOn: date }));
      }
      await protection.onScored(scored);
    },
  });

  // Breach and domain checks on the address someone signs in with. Never in the blocking path of
  // a login, and every failure is "not checked" rather than "clean" (security/email-reputation.js).
  const emailReputation = reputation || createReputationService({
    stores,
    onError: (err) => console.error('Email reputation:', err.message),
  });

  // A cost the browser pays before a sign-in or sign-up is looked at (security/proof-of-work.js).
  const pow = proofOfWork || createProofOfWork({ now });

  // Writes the paragraph an analyst would otherwise write by hand. It is handed catalogue keys
  // and numbers and nothing else - see the note at the top of security/ai-analyst.js on why an
  // app that detects data going into models must not send any of its own.
  const analyst = ai || createAiAnalyst({ onError: (err) => console.error('AI analyst:', err.message) });

  return {
    db,
    stores,
    sessions,
    passwords,
    throttle,
    limits: rateLimits,
    telemetry,
    crimguard,
    maxFileBytes,
    sessionPolicy,
    now,
    protection,
    reputation: emailReputation,
    pow,
    env,
    ai: analyst,
  };
}

module.exports = { createServices };
