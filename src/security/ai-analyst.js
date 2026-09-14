'use strict';

// A model used as an analyst's assistant: it reads what the engine already decided and writes the
// paragraph a human would otherwise write by hand.
//
// ---------------------------------------------------------------------------------------------
// The rule this module exists to keep.
//
// Red's whole job is noticing documents being fed into external models (security/genai.js). An
// integration that posted file contents, pasted text, or people's names and addresses to a
// third-party API would be doing the exact thing the product flags - and would deserve to be
// flagged for it.
//
// So nothing free-form is ever sent. Every request is assembled here, field by field, from values
// the engine produced: variable names out of the fixed catalogue, numbers, levels, category names,
// counts, dates. There is no code path that puts a file's contents, a person's name, an email
// address, a project title, a search term, or the text of a paste into a prompt, because the
// builders below only accept the typed shapes and drop everything else.
//
// What the model gets is therefore a table of numbers about an anonymous subject, and what it gives
// back is prose about those numbers. It never decides anything: the score, the level, the scenario
// and every action Red takes are the engine's, computed before this is called. If the model is
// slow, wrong, rate-limited or switched off, the console shows exactly what it showed before -
// the explanation is the only thing missing.
// ---------------------------------------------------------------------------------------------

const ENDPOINT = 'https://api.groq.com/openai/v1/chat/completions';
const DEFAULT_MODEL = 'llama-3.3-70b-versatile';
const TIMEOUT_MS = 12_000;
const MAX_TOKENS = 500;

// Free tier is 30 requests a minute. One explanation per person per view would burn that in a
// busy console, so answers are cached and identical requests are collapsed.
const CACHE_MS = 10 * 60 * 1000;

const SYSTEM = [
  'You are a senior insider-risk analyst writing for other analysts.',
  'You are given the output of a detection engine: feature names from a fixed catalogue, z-scores,',
  'weights and contributions. Explain what the numbers suggest, in plain English.',
  '',
  'Rules:',
  '- Be concise. Three or four sentences, or short bullets. No preamble, no restating the question.',
  '- Say what the evidence is and what it is consistent with. Distinguish "unusual" from "malicious".',
  '- Name the specific variables that drove it. Use their plain-English sense, not the raw key.',
  '- If context explains it (an approved ticket, a migration), say so plainly.',
  '- Never invent a name, a file, a system or a number you were not given.',
  '- You are not deciding anything. Do not recommend firing, disciplining or accusing anyone.',
  '- If the evidence is thin, say it is thin. That is a useful answer.',
].join('\n');

// --- payload builders -------------------------------------------------------------------------
//
// Each one takes the engine's own output and returns only primitives. Anything not explicitly
// picked here never reaches the network.

const num = (value, digits = 1) => (Number.isFinite(Number(value)) ? Number(Number(value).toFixed(digits)) : null);
const word = (value, max = 40) => (typeof value === 'string' ? value.replace(/[^\w .:-]/g, '').slice(0, max) : null);

// A feature contribution, reduced to the catalogue key and the numbers behind it. The key is one
// of the 100 fixed names, so it carries nothing about the person.
const contribution = (row) => ({
  feature: word(row.featureKey ?? row.feature_key ?? row.feature, 60),
  points: num(row.points ?? row.contribution, 2),
  z: num(row.z ?? row.zScore, 2),
  observed: num(row.observed ?? row.value, 2),
  baseline: num(row.baseline ?? row.median, 2),
  detector: word(row.detector, 20),
  explained: num(row.contextConfidence ?? row.c, 2),
});

// One person's day, as numbers. Deliberately no id, no name, no email, no project, no file.
function scorePayload({ score, level, scenario, contributions = [], categories = [], hrAmplifier, contextMultiplier, days }) {
  return {
    subject: 'an account',
    score: num(score),
    level: word(level, 12),
    scenario: word(scenario, 40),
    hr_amplifier: num(hrAmplifier, 2),
    context_multiplier: num(contextMultiplier, 2),
    history_days: num(days, 0),
    top_features: contributions.slice(0, 10).map(contribution).filter((row) => row.feature),
    categories: categories.slice(0, 8).map((row) => ({ category: word(row.category ?? row.name, 40), strength: num(row.strength ?? row.R, 2) })),
  };
}

// Shadow-AI egress, as counts by destination category. The destination *category* goes; the
// document names and the people do not.
function egressPayload(events = []) {
  const byDestination = new Map();
  for (const event of events) {
    const key = word(event.destination, 60) || 'unknown';
    const row = byDestination.get(key) || { destination: key, category: word(event.category, 30), events: 0, chars: 0, patterns: new Set() };
    row.events += 1;
    row.chars += Number(event.chars) || 0;
    for (const pattern of event.patterns || []) row.patterns.add(word(pattern, 30));
    byDestination.set(key, row);
  }
  return {
    window: 'today',
    accounts: new Set(events.map((event) => event.person?.redUserId ?? 'self')).size,
    destinations: [...byDestination.values()].slice(0, 12).map((row) => ({
      destination: row.destination, category: row.category, events: row.events,
      characters: row.chars, patterns: [...row.patterns].filter(Boolean).slice(0, 6),
    })),
  };
}

// --- the client -------------------------------------------------------------------------------

function createAiAnalyst({
  apiKey = process.env.GROQ_API_KEY,
  model = process.env.GROQ_MODEL || DEFAULT_MODEL,
  fetchImpl = fetch,
  now = Date.now,
  cacheMs = CACHE_MS,
  onError = () => {},
} = {}) {
  const cache = new Map();
  const inFlight = new Map();

  const enabled = () => Boolean(apiKey);

  async function ask(prompt, { key }) {
    if (!enabled()) return null;
    const hit = cache.get(key);
    if (hit && now() - hit.at < cacheMs) return hit.text;
    if (inFlight.has(key)) return inFlight.get(key);

    const run = (async () => {
      try {
        const res = await fetchImpl(ENDPOINT, {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
          body: JSON.stringify({
            model,
            temperature: 0.2,
            max_tokens: MAX_TOKENS,
            messages: [
              { role: 'system', content: SYSTEM },
              { role: 'user', content: prompt },
            ],
          }),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        if (!res.ok) throw new Error(`Groq ${res.status}`);
        const data = await res.json();
        const text = data?.choices?.[0]?.message?.content?.trim() || null;
        if (text) cache.set(key, { at: now(), text });
        return text;
      } catch (err) {
        // The console is fully usable without this. A failure costs the paragraph, nothing else.
        onError(err);
        return null;
      } finally {
        inFlight.delete(key);
      }
    })();
    inFlight.set(key, run);
    return run;
  }

  return {
    enabled,
    model,

    // Why this account scores what it scores.
    async explainScore(input) {
      const payload = scorePayload(input);
      if (payload.score === null) return null;
      return ask(
        `Explain this insider-risk assessment to an analyst.\n\n${JSON.stringify(payload, null, 1)}`,
        { key: `score:${payload.score}:${payload.scenario}:${payload.top_features.map((f) => f.feature).join(',')}` },
      );
    },

    // What today's shadow-AI traffic amounts to, and what an analyst should look at first.
    async triageEgress(events) {
      const payload = egressPayload(events);
      if (!payload.destinations.length) return null;
      return ask(
        'Work from this summary of company data leaving into external services, mostly AI assistants. '
        + 'Say what stands out, what is probably ordinary, and what an analyst should check first.\n\n'
        + JSON.stringify(payload, null, 1),
        { key: `egress:${JSON.stringify(payload.destinations)}` },
      );
    },

    // Exposed so a test, or a careful reader, can see exactly what would be sent.
    preview: { scorePayload, egressPayload },
  };
}

module.exports = { createAiAnalyst, scorePayload, egressPayload, DEFAULT_MODEL, SYSTEM };
