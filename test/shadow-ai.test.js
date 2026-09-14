'use strict';

// Shadow AI: work from inside Red arriving at a model nobody sanctioned.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { connectCrimGuard } = require('../src/db/crimguard');
const {
  classify, assess, burstsIn, hostOf, isShadowAi, CATEGORIES, LARGE_PASTE_CHARS,
} = require('../src/security/genai');
const { startApp } = require('./helpers');

// --- telling destinations apart ------------------------------------------------------------------

test('a host is reduced to its registrable form, however it was reported', () => {
  assert.equal(hostOf('https://user:pw@Chatgpt.com:443/c/abc?x=1#y'), 'chatgpt.com');
  assert.equal(hostOf('CHATGPT.COM'), 'chatgpt.com');
  assert.equal(hostOf(''), null);
  assert.equal(hostOf(null), null);
});

test('a model is told from anything that merely looks like one', () => {
  const genai = (d) => classify(d).category === CATEGORIES.GENAI;
  assert.equal(genai('chatgpt.com'), true);
  assert.equal(genai('https://claude.ai/chat/1'), true);
  assert.equal(genai('api.openai.com'), true);
  assert.equal(genai('eu.chatgpt.com'), true, 'any subdomain counts');

  // The two mistakes a sloppy substring match makes, and neither is made here.
  assert.equal(genai('notopenai.com'), false, 'ends with the same letters, different company');
  assert.equal(genai('openai.com.evil.test'), false, 'the real domain is only a prefix');

  // Path-scoped entries: Copilot is a model, the rest of GitHub is not.
  assert.equal(genai('https://github.com/copilot'), true);
  assert.equal(genai('https://github.com/anthropics/anthropic-sdk'), false);

  // The other destinations stay their own categories rather than all becoming "AI".
  assert.equal(classify('drive.google.com').category, CATEGORIES.PERSONAL_CLOUD);
  assert.equal(classify('mail.google.com').category, CATEGORIES.WEBMAIL);
  assert.equal(classify('pastebin.com').category, CATEGORIES.EPHEMERAL);
  assert.equal(classify('wetransfer.com').category, CATEGORIES.FILE_SHARING);
  assert.equal(classify('intranet.example.test').category, CATEGORIES.OTHER);
});

test('an extension that wraps a model is caught by its id', () => {
  const verdict = classify(null, { extensionId: 'oallhdmefljfmoncmbpghaogmlbfglfp' });
  assert.equal(verdict.category, CATEGORIES.GENAI);
  assert.equal(verdict.app, 'Sider AI');
  assert.equal(classify(null, { extensionId: 'some-ordinary-extension' }).category, null);
});

test("the organisation's own sanctioned tenant is not shadow AI", () => {
  const known = [{ domain: 'chatgpt.com', app_name: 'ChatGPT Enterprise', category: 'genai_llm', is_sanctioned: true }];
  const verdict = classify('chatgpt.com', { known });
  assert.equal(verdict.category, CATEGORIES.GENAI);
  assert.equal(verdict.sanctioned, true);
  assert.equal(isShadowAi(verdict), false, 'the thing people are meant to use instead');
  assert.equal(isShadowAi(classify('chatgpt.com')), true, 'and the public one still is');
});

// --- how bad is it ------------------------------------------------------------------------------

test('severity comes from what went, and where, and says why', () => {
  const quiet = assess({ destination: 'intranet.example.test', chars: 40 });
  assert.equal(quiet.level, 'low');
  assert.equal(quiet.shadowAi, false);

  const bad = assess({
    destination: 'chatgpt.com',
    chars: 9000,
    sensitivity: 4,
    patterns: ['api_key'],
    document: { name: 'term-sheet.pdf', project: 'Northwind' },
  });
  assert.equal(bad.shadowAi, true);
  assert.equal(bad.level, 'critical');
  assert.ok(bad.reasons.some((r) => /Unsanctioned model/.test(r)));
  assert.ok(bad.reasons.some((r) => /term-sheet\.pdf/.test(r)), 'names the document, which is the whole claim');
  assert.ok(bad.reasons.some((r) => /api_key/.test(r)));

  // The same volume somewhere ordinary is not the same event.
  const elsewhere = assess({ destination: 'intranet.example.test', chars: 9000 });
  assert.ok(elsewhere.severity < bad.severity);
  // A small quote into a model is noted, not shouted about.
  assert.equal(assess({ destination: 'chatgpt.com', chars: 100 }).level, 'medium');
});

test('a document handed over in pieces is one burst, not three events', () => {
  const t0 = Date.parse('2026-09-15T10:00:00Z');
  const at = (seconds, chars) => ({ occurredAt: new Date(t0 + seconds * 1000).toISOString(), chars });

  const bursts = burstsIn([at(0, 4000), at(60, 4000), at(120, 4000), at(180, 4000)]);
  assert.equal(bursts.length, 1, 'one run of copies, not one burst per copy');
  assert.equal(bursts[0].copies, 4);
  assert.equal(bursts[0].chars, 16000);

  // The same volume spread across the day is how people work.
  assert.equal(burstsIn([at(0, 9000), at(3600, 9000), at(7200, 9000)]).length, 0);
  // And three small copies are not a document.
  assert.equal(burstsIn([at(0, 50), at(10, 50), at(20, 50)]).length, 0);
  assert.equal(LARGE_PASTE_CHARS > 1000, true);
});

// --- end to end ---------------------------------------------------------------------------------

let crimguard;
let app;
before(async () => {
  crimguard = await connectCrimGuard({ mode: 'sqlite', sqlitePath: ':memory:' });
  app = await startApp({ crimguard, riskInterval: 0, env: { ...process.env, RED_EGRESS_KEY: 'test-agent-key' } });
});
after(async () => { app.close(); await crimguard.close(); });

async function uploadTo(b, projectName, fileName, text) {
  const project = (await b('POST', '/api/projects', { name: projectName })).body.project;
  const res = await fetch(`${app.base}/api/projects/${project.id}/files`, {
    method: 'POST',
    headers: { cookie: b.getCookie(), 'content-type': 'application/octet-stream', 'x-file-name': encodeURIComponent(fileName) },
    body: Buffer.from(text),
  });
  return { project, file: (await res.json()).file };
}

test('a session reports only its own egress, and Red fills in the document itself', async () => {
  const person = await app.signUp('Sam Shadow');
  const { file } = await uploadTo(person.b, 'Acquisition', 'term-sheet.txt', 'Indicative offer: 240m.');

  // An admin marks it Restricted, so the confidentiality is Red's to know, not the reporter's.
  const admin = await app.signInAdmin();
  await admin.b('PUT', `/api/files/${file.id}/access`, { confidentiality: 4, roles: [], people: [person.user.id] });

  const reported = await person.b('POST', '/api/telemetry/egress', {
    channel: 'clipboard',
    destination: 'https://chatgpt.com/c/9f2',
    chars: 9000,
    fileId: file.id,
    patterns: ['api_key'],
  });
  assert.equal(reported.status, 202, JSON.stringify(reported.body));
  const [verdict] = reported.body.results;
  assert.equal(verdict.shadowAi, true);
  assert.equal(verdict.level, 'critical');
  assert.equal(verdict.document.name, 'term-sheet.txt');
  assert.ok(verdict.reasons.some((r) => /level 4/.test(r)), 'the level came from Red, not the reporter');

  // It reaches the activity log, naming the destination and the document.
  const activity = (await admin.b('GET', '/api/admin/audit?limit=20')).body.events;
  const logged = activity.find((event) => event.action === 'security.shadow_ai_egress');
  assert.ok(logged, 'a shadow-AI egress is an event worth keeping');
  assert.equal(logged.details.destination, 'chatgpt.com');
  assert.equal(logged.details.document, 'term-sheet.txt');

  // And the person can read what was said about them.
  const mine = await person.b('GET', '/api/me/egress');
  assert.equal(mine.status, 200);
  assert.ok(mine.body.events.length >= 1);
});

test('a reporter cannot describe anyone but itself without the agent key', async () => {
  const person = await app.signUp('Nia Normal');
  const victim = await app.signUp('Vic Victim');

  // A signed-in session naming someone else is ignored: the account comes from the cookie.
  const spoof = await person.b('POST', '/api/telemetry/egress', {
    email: victim.email, destination: 'chatgpt.com', chars: 5000,
  });
  assert.equal(spoof.status, 202);
  assert.equal((await victim.b('GET', '/api/me/egress')).body.events.length, 0, 'nothing was written against them');

  // With no session and no key, the door is shut.
  const anon = app.browser();
  const refused = await anon('POST', '/api/telemetry/egress', { email: victim.email, destination: 'chatgpt.com', chars: 5000 });
  assert.equal(refused.status, 401);
});

test('an endpoint agent reports for a named subject, which is the point of it', async () => {
  const person = await app.signUp('Ed Endpoint');
  const anon = app.browser();
  const res = await anon('POST', '/api/telemetry/egress', {
    email: person.email,
    events: [
      { channel: 'extension', extensionId: 'oallhdmefljfmoncmbpghaogmlbfglfp', chars: 12000 },
      { channel: 'upload', destination: 'drive.google.com', bytes: 5_000_000, document: { name: 'export.csv' } },
    ],
  }, { 'x-red-agent-key': 'test-agent-key' });

  assert.equal(res.status, 202, JSON.stringify(res.body));
  assert.equal(res.body.accepted, 2);
  assert.equal(res.body.results[0].shadowAi, true, 'the extension is a model wrapper');
  assert.equal(res.body.results[0].app, 'Sider AI');
  assert.equal(res.body.results[1].category, CATEGORIES.PERSONAL_CLOUD, 'and personal cloud stays its own thing');

  const wrongKey = await anon('POST', '/api/telemetry/egress', { email: person.email, destination: 'chatgpt.com' }, { 'x-red-agent-key': 'not-the-key' });
  assert.equal(wrongKey.status, 401);
});

test('the admin feed separates shadow AI from everything else, and is admins only', async () => {
  const person = await app.signUp('Fay Feed');
  await person.b('POST', '/api/telemetry/egress', { destination: 'chatgpt.com', chars: 6000 });
  await person.b('POST', '/api/telemetry/egress', { destination: 'intranet.example.test', chars: 20 });
  await app.server.telemetry.flush();

  const admin = await app.signInAdmin();
  const feed = await admin.b('GET', '/api/admin/egress');
  assert.equal(feed.status, 200);
  assert.ok(feed.body.events.length >= 2);
  assert.ok(feed.body.shadowAi >= 1);
  assert.equal(feed.body.reporting, true, 'an agent key is configured');

  const onlyShadow = await admin.b('GET', '/api/admin/egress?shadow=1');
  assert.ok(onlyShadow.body.events.every((event) => event.category === CATEGORIES.GENAI));

  assert.equal((await person.b('GET', '/api/admin/egress')).status, 403);
});

// --- the AI analyst, and what it is never allowed to send ----------------------------------------
//
// Red exists to notice documents going into external models. An integration that sent Red's own
// documents to one would be the very thing it flags, so the payload builders are an allowlist and
// this is the test that keeps them one.

const { createAiAnalyst, scorePayload, egressPayload } = require('../src/security/ai-analyst');

test('nothing identifying can reach the prompt, however it is smuggled in', () => {
  const payload = scorePayload({
    score: 72.9,
    level: 'high',
    scenario: 'slow_exfiltration',
    hrAmplifier: 1.35,
    days: 210,
    // Every field below that is not a catalogue key or a number is something that must not leave.
    contributions: [{
      featureKey: 'files_accessed_count', points: 18.2, z: 4.1, observed: 70, baseline: 15, detector: 'drift',
      name: 'Marcus Webb', email: 'marcus@red.local', fileName: 'northwind-term-sheet.md',
      excerpt: 'Indicative offer: 240m', secret: 'sk_live_51H8xY2abcdefgh',
    }],
    categories: [{ category: 'data_movement', strength: 0.81, note: 'Acquisition — Northwind' }],
    ownerName: 'Priya Raman',
    projectTitle: 'Payroll & compensation FY26',
    rawText: 'the entire contents of a confidential file',
  });

  const json = JSON.stringify(payload).toLowerCase();
  for (const forbidden of [
    'marcus', 'marcus@red.local', 'northwind', 'term-sheet', 'indicative offer',
    'sk_live', 'priya', 'payroll', 'acquisition', 'entire contents',
  ]) {
    assert.equal(json.includes(forbidden.toLowerCase()), false, `${forbidden} must never reach the model`);
  }

  // What does go is the catalogue key and the numbers behind it, which is enough to explain a score.
  assert.equal(payload.top_features[0].feature, 'files_accessed_count');
  assert.equal(payload.top_features[0].z, 4.1);
  assert.equal(payload.subject, 'an account');
});

test('the egress summary carries destinations, never the people at them', () => {
  const json = JSON.stringify(egressPayload([
    { destination: 'chatgpt.com', category: 'genai_llm', chars: 9000, patterns: ['api_key'],
      person: { redUserId: 3, name: 'Luca Moretti', email: 'luca@red.local' } },
    { destination: 'chatgpt.com', category: 'genai_llm', chars: 1000, patterns: [],
      person: { redUserId: 3, name: 'Luca Moretti', email: 'luca@red.local' } },
  ]));
  assert.equal(json.includes('Luca'), false);
  assert.equal(json.includes('luca@red.local'), false);
  assert.match(json, /chatgpt\.com/);
  assert.match(json, /"events":2/, 'the two are counted together');
  assert.match(json, /"characters":10000/);
});

test('with no key the analyst is simply off, and a failure costs only the paragraph', async () => {
  const off = createAiAnalyst({ apiKey: '' });
  assert.equal(off.enabled(), false);
  assert.equal(await off.explainScore({ score: 80, contributions: [] }), null);

  const broken = createAiAnalyst({ apiKey: 'k', fetchImpl: async () => { throw new Error('rate limited'); } });
  assert.equal(broken.enabled(), true);
  assert.equal(await broken.explainScore({ score: 80, level: 'high', contributions: [] }), null, 'never throws at the caller');

  // A good answer comes back, and a repeat is served from cache rather than spending the quota.
  let calls = 0;
  const ok = createAiAnalyst({
    apiKey: 'k',
    fetchImpl: async () => { calls += 1; return { ok: true, json: async () => ({ choices: [{ message: { content: '  Looks like a slow creep.  ' } }] }) }; },
  });
  const input = { score: 72.9, level: 'high', scenario: 'slow_exfiltration', contributions: [{ featureKey: 'files_accessed_count', points: 18 }] };
  assert.equal(await ok.explainScore(input), 'Looks like a slow creep.');
  assert.equal(await ok.explainScore(input), 'Looks like a slow creep.');
  assert.equal(calls, 1, 'the free tier is 30 requests a minute; identical questions ask once');
});
