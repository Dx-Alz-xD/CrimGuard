'use strict';

// What two public services know about an address: whether it turns up in breach corpora
// (XposedOrNot) and whether its domain is a throwaway, a forwarder or not a real mail domain
// (mailcheck, via RapidAPI).
//
// Three rules this module keeps, because it is the only part of Red that talks to anyone else:
//
//   never blocking   it is called *after* a session has been issued, never before. If a provider
//                    is slow or down, people still sign in. Nothing here can keep anyone out.
//   fails open       an error, a timeout, a missing API key and a rate limit all come back as
//                    `null`, which means *not checked* - never `false`. "The provider is down"
//                    and "the address is fine" are different facts, and writing the first as the
//                    second would quietly clear an address nobody ever looked at. The snapshot
//                    pipeline already draws this line (telemetry/coverage.js); so does this.
//   says what it sends  an address is sent to both services. /privacy says so, and the person
//                    can read the result on their own risk panel.
//
// No API key is ever written into the source: the RapidAPI key comes from RED_MAILCHECK_KEY, and
// without it the domain half is simply not checked.

const { emailAdjustments } = require('./risk-signals');

const XPOSED_URL = 'https://api.xposedornot.com/v1/check-email/';
const MAILCHECK_HOST = 'mailcheck.p.rapidapi.com';
const TIMEOUT_MS = 6000;

// Not checked at all, for every field. The shape every failure returns.
const UNKNOWN = Object.freeze({
  breached: null, breachCount: null, breaches: [],
  disposable: null, valid: null, blocked: null, detail: {},
});

const domainOf = (email) => String(email).split('@').pop().trim().toLowerCase();

async function getJson(url, { headers = {}, timeoutMs = TIMEOUT_MS, fetchImpl = fetch } = {}) {
  const res = await fetchImpl(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

// XposedOrNot answers 200 either way: a hit carries `breaches`, a miss carries `{ Error: 'Not
// found' }`. A 404-or-nothing reading of it would call every breached address clean.
async function checkBreaches(email, options = {}) {
  try {
    const data = await getJson(XPOSED_URL + encodeURIComponent(email), options);
    // The list arrives wrapped one level deeper than it looks: { breaches: [[ "Site", ... ]] }.
    const names = Array.isArray(data?.breaches) ? (data.breaches[0] ?? []) : [];
    if (!Array.isArray(names) || names.length === 0) {
      return { breached: false, breachCount: 0, breaches: [] };
    }
    const clean = names.filter((name) => typeof name === 'string').map((name) => name.slice(0, 80));
    return {
      breached: true,
      breachCount: clean.length,
      // Enough to show the person which services, without keeping an unbounded list per account.
      breaches: clean.slice(0, 25),
    };
  } catch {
    return { breached: null, breachCount: null, breaches: [] };
  }
}

// mailcheck is a domain service, so this says nothing about whether the mailbox exists - only
// whether mail to that domain is deliverable, disposable, forwarded or blocklisted.
async function checkDomain(domain, { key = process.env.RED_MAILCHECK_KEY, ...options } = {}) {
  if (!key) return { disposable: null, valid: null, blocked: null, detail: {} };
  try {
    const data = await getJson(`https://${MAILCHECK_HOST}/?domain=${encodeURIComponent(domain)}`, {
      ...options,
      headers: { 'x-rapidapi-key': key, 'x-rapidapi-host': MAILCHECK_HOST },
    });
    return {
      // A forwarder is a throwaway for our purposes: mail reaches somewhere we cannot see.
      disposable: Boolean(data.disposable || data.email_forwarder),
      valid: data.valid !== false,
      blocked: Boolean(data.block),
      detail: {
        text: typeof data.text === 'string' ? data.text.slice(0, 120) : null,
        reason: typeof data.reason === 'string' ? data.reason.slice(0, 120) : null,
        risk: Number.isFinite(data.risk) ? data.risk : null,
        mxHost: typeof data.mx_host === 'string' ? data.mx_host.slice(0, 120) : null,
        // A typo suggestion is the most useful thing here for an ordinary user.
        possibleTypo: Array.isArray(data.possible_typo) ? data.possible_typo.slice(0, 3) : [],
      },
    };
  } catch {
    return { disposable: null, valid: null, blocked: null, detail: {} };
  }
}

// Both checks for one address. Run together, because neither depends on the other and a sign-in
// should not wait for two round trips in series.
async function checkEmail(email, options = {}) {
  const domain = domainOf(email);
  if (!domain || !domain.includes('.')) {
    return { ...UNKNOWN, domain, valid: false, detail: { text: 'Not a routable domain.' } };
  }
  const [breaches, reputation] = await Promise.all([
    checkBreaches(email, options),
    checkDomain(domain, options),
  ]);
  return { domain, ...breaches, ...reputation };
}

// Whether Red will check at all. Off with no key and no explicit opt-in, so a deployment that
// wants nothing sent anywhere gets exactly that.
const enabled = (env = process.env) => env.RED_EMAIL_CHECKS !== '0';

// --- the service the app uses ------------------------------------------------------------------

// Checks an address after sign-in and turns the answer into risk adjustments. Nothing here is
// awaited by the login route: refresh() returns a promise the caller is free to drop.
function createReputationService({ stores, check = checkEmail, maxAgeMs = 7 * 24 * 60 * 60 * 1000, env = process.env, now = Date.now, onError = () => {} } = {}) {
  const { signals } = stores;
  const holdFor = () => new Date(now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  // One check per account at a time, so two tabs signing in together make one round trip.
  const inFlight = new Map();

  // Every email_* adjustment this module owns, so a re-check that finds nothing withdraws what an
  // earlier one added rather than leaving a stale penalty on the account forever.
  const OWNED = ['email_breached', 'email_disposable', 'email_blocked', 'email_invalid'];

  function apply(userId, reputation) {
    const wanted = new Map(emailAdjustments(reputation).map((a) => [a.kind, a]));
    for (const kind of OWNED) {
      const adjustment = wanted.get(kind);
      if (adjustment) {
        signals.put(userId, { ...adjustment, detail: { domain: reputation.domain }, expiresAt: holdFor() });
      } else {
        signals.drop(userId, kind);
      }
    }
  }

  function fresh(userId) {
    const existing = signals.reputation(userId);
    if (!existing?.checkedAt) return null;
    const age = now() - Date.parse(existing.checkedAt.replace(' ', 'T') + 'Z');
    return Number.isFinite(age) && age < maxAgeMs ? existing : null;
  }

  return {
    enabled: () => enabled(env),

    // What the person is shown, and what the admin console reads. Never triggers a check.
    read: (userId) => signals.reputation(userId),

    // Checks if the cached answer is stale, writes it, and re-applies the adjustments.
    async refresh(user, { force = false } = {}) {
      if (!enabled(env)) return null;
      if (!force) {
        const cached = fresh(user.id);
        if (cached) return cached;
      }
      if (inFlight.has(user.id)) return inFlight.get(user.id);

      const run = (async () => {
        try {
          const reputation = await check(user.email, { key: env.RED_MAILCHECK_KEY });
          stores.signals.putReputation(user.id, reputation);
          apply(user.id, reputation);
          return signals.reputation(user.id);
        } catch (err) {
          // A provider being down must never turn into a failed sign-in, or a wrong adjustment.
          onError(err);
          return null;
        } finally {
          inFlight.delete(user.id);
        }
      })();
      inFlight.set(user.id, run);
      return run;
    },
  };
}

module.exports = { UNKNOWN, domainOf, checkBreaches, checkDomain, checkEmail, enabled, createReputationService };
