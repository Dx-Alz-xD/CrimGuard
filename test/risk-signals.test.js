'use strict';

// The proof-of-work on sign-in, the OTP step-up and its discount, the email checks, and the
// upload block — everything that sits between a score and what an account may do.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createStores } = require('../src/db');
const { createProofOfWork, solve, leadingZeroBits, meets } = require('../src/security/proof-of-work');
const { createReputationService, checkEmail } = require('../src/security/email-reputation');
const {
  MFA, effectiveScore, uploadBlocked, mfaRequired, otpValid, emailAdjustments, assertDemoOtpAllowed,
} = require('../src/security/risk-signals');
const { startApp, PASSWORD } = require('./helpers');

const MINUTE = 60_000;

// --- the rules, on their own -------------------------------------------------------------------

test('the effective score is the engine plus every live delta, clamped', () => {
  assert.equal(effectiveScore(50, []), 50);
  assert.equal(effectiveScore(80, [-25]), 55);
  assert.equal(effectiveScore(80, [-25, 8]), 63);
  assert.equal(effectiveScore(5, [-25]), 0, 'never below zero');
  assert.equal(effectiveScore(95, [25]), 100, 'never above a hundred');
  assert.equal(effectiveScore(null, [-25]), null, 'an unscored account has nothing to adjust');
});

test('uploads stop at the limiting threshold, and an exemption lifts them', () => {
  assert.equal(uploadBlocked({ score: 74 }), false);
  assert.equal(uploadBlocked({ score: 75 }), true);
  assert.equal(uploadBlocked({ score: 99 }), true);
  assert.equal(uploadBlocked({ score: 99, exempt: true }), false, 'the same waiver that lifts limiting');
  assert.equal(uploadBlocked({ score: null }), false, 'nobody scored yet');
});

test('the step-up waits for the score to stay high, not just to be high', () => {
  const high = { score: 90, now: Date.now() };
  assert.equal(mfaRequired({ ...high, sessionAgeMs: 0 }), false, 'not the moment they land');
  assert.equal(mfaRequired({ ...high, sessionAgeMs: MFA.dwellMs - 1 }), false);
  assert.equal(mfaRequired({ ...high, sessionAgeMs: MFA.dwellMs }), true);
  assert.equal(mfaRequired({ score: 84, sessionAgeMs: 10 * MINUTE }), false, 'below the threshold');

  const now = Date.now();
  const justPassed = new Date(now - 1000).toISOString();
  const longAgo = new Date(now - MFA.holdsForMs - 1000).toISOString();
  assert.equal(mfaRequired({ score: 90, sessionAgeMs: 10 * MINUTE, passedAt: justPassed, now }), false);
  assert.equal(mfaRequired({ score: 90, sessionAgeMs: 10 * MINUTE, passedAt: longAgo, now }), true, 'and it expires');
});

test('the demo code is accepted, and production has to say it wants it', () => {
  assert.equal(otpValid('123456'), true);
  assert.equal(otpValid(' 123456 '), true);
  assert.equal(otpValid('000000'), false);
  assert.equal(otpValid(123456), false, 'not a string');

  assert.doesNotThrow(() => assertDemoOtpAllowed({ NODE_ENV: 'development' }));
  assert.throws(() => assertDemoOtpAllowed({ NODE_ENV: 'production' }), /demo code/);
  assert.doesNotThrow(() => assertDemoOtpAllowed({ NODE_ENV: 'production', RED_ALLOW_DEMO_OTP: '1' }));
});

test('email findings become one adjustment each, and nothing found costs nothing', () => {
  assert.deepEqual(emailAdjustments(null), []);
  assert.deepEqual(emailAdjustments({ breached: false, disposable: false, valid: true, blocked: false }), []);
  assert.deepEqual(
    emailAdjustments({ breached: null, disposable: null, valid: null, blocked: null }),
    [],
    'not checked is not the same as clean, and costs nothing either way',
  );

  const one = emailAdjustments({ breached: true, breachCount: 1 });
  assert.deepEqual(one.map((a) => a.kind), ['email_breached']);
  const many = emailAdjustments({ breached: true, breachCount: 200 });
  assert.ok(many[0].delta > one[0].delta, 'more breaches costs more');
  assert.ok(many[0].delta <= 18, 'up to a cap');

  const throwaway = emailAdjustments({ breached: false, disposable: true, blocked: true, valid: false });
  assert.deepEqual(throwaway.map((a) => a.kind).sort(), ['email_disposable', 'email_invalid']);
});

// --- proof of work ------------------------------------------------------------------------------

test('a challenge is single-use, signed, and expires', () => {
  const pow = createProofOfWork({ baseDifficulty: 8 });
  const { challenge, difficulty } = pow.issue();
  const solution = solve(challenge, difficulty);

  assert.equal(pow.check(challenge, solution), null);
  assert.equal(pow.check(challenge, solution), 'already_used', 'one solved puzzle buys one attempt');

  const next = pow.issue();
  assert.equal(pow.check(next.challenge, '0'), 'unsolved');
  assert.equal(pow.check(`${next.challenge.slice(0, -4)}AAAA`, '0'), 'forged');
  assert.equal(pow.check('not.a.challenge', '0'), 'malformed');
  assert.equal(pow.check(next.challenge, 'abc'), 'malformed', 'a solution is a number');
  assert.equal(pow.check(undefined, undefined), 'missing');

  const stale = createProofOfWork({ ttlMs: -1 });
  assert.equal(stale.check(stale.issue().challenge, '0'), 'expired');
});

test('the puzzle gets harder for a client that keeps failing', () => {
  const pow = createProofOfWork({ baseDifficulty: 16 });
  assert.equal(pow.difficultyFor(0), 16);
  assert.ok(pow.difficultyFor(10) > pow.difficultyFor(0));
  assert.ok(pow.difficultyFor(1000) <= 22, 'but never past a cost an honest person would notice');
  assert.equal(leadingZeroBits(Buffer.from([0, 0, 0x0f])), 20);
  assert.equal(meets('x', '0', 0), true);
});

// --- end to end ---------------------------------------------------------------------------------

let app;
let stores;
before(async () => { app = await startApp(); stores = createStores(app.db); });
after(() => app.close());

const score = (userId, value) =>
  stores.risk.setState(userId, { score: value, level: value >= 90 ? 'critical' : 'high', scenario: null, scoredOn: '2026-09-15' });

async function upload(b, projectId, name = 'f.txt') {
  const res = await fetch(`${app.base}/api/projects/${projectId}/files`, {
    method: 'POST',
    headers: { cookie: b.getCookie(), 'content-type': 'application/octet-stream', 'x-file-name': name },
    body: Buffer.from('some bytes'),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

test('signing in needs a solved challenge, and a wrong one is refused', async () => {
  const person = await app.signUp('Polly Proof');
  const bare = app.browser();

  // The helper attaches a solution; passing an explicit bad one opts out of that.
  const forged = await bare('POST', '/api/login', { email: person.email, password: PASSWORD, portal: 'user', challenge: 'not.a.real.challenge.x', solution: '1' });
  assert.equal(forged.status, 400);
  assert.equal(forged.body.code, 'challenge_failed');

  const proof = await app.proveWork();
  const good = await bare('POST', '/api/login', { email: person.email, password: PASSWORD, portal: 'user', ...proof });
  assert.equal(good.status, 200, JSON.stringify(good.body));

  // That same solution cannot be spent twice. A spent challenge reads as stale rather than
  // hostile, because a tab left open hits it for the same reason a replay does — and the page
  // just fetches another.
  const replay = await app.browser()('POST', '/api/login', { email: person.email, password: PASSWORD, portal: 'user', ...proof });
  assert.equal(replay.status, 400);
  assert.equal(replay.body.code, 'challenge_stale');
});

test('a risky account cannot upload, and can still read what it has', async () => {
  const person = await app.signUp('Ricky Risk');
  const project = (await person.b('POST', '/api/projects', { name: 'Work' })).body.project;
  const first = await upload(person.b, project.id, 'before.txt');
  assert.equal(first.status, 201, 'uploading is ordinary until the score says otherwise');

  score(person.user.id, 80);
  const blocked = await upload(person.b, project.id, 'after.txt');
  assert.equal(blocked.status, 403);
  assert.equal(blocked.body.code, 'uploads_blocked');

  // Replacing a file's contents is putting material in too.
  const replace = await fetch(`${app.base}/api/projects/${project.id}/files/${first.body.file.id}/content`, {
    method: 'PUT',
    headers: { cookie: person.b.getCookie(), 'content-type': 'application/octet-stream' },
    body: Buffer.from('new bytes'),
  });
  assert.equal(replace.status, 403);

  // Reading, listing and deleting are untouched: this narrows what comes in, not their own work.
  assert.equal((await person.b('GET', `/api/projects/${project.id}/files`)).status, 200);
  const read = await fetch(`${app.base}/api/projects/${project.id}/files/${first.body.file.id}/download`, { headers: { cookie: person.b.getCookie() } });
  assert.equal(read.status, 200);

  // An admin's waiver lifts it, the same one that lifts limiting.
  const admin = await app.signInAdmin();
  stores.risk.exempt(person.user.id, { by: { id: admin.user.id, name: admin.user.name, role: admin.user.role }, reason: 'known migration' });
  assert.equal((await upload(person.b, project.id, 'allowed.txt')).status, 201);
  stores.risk.unexempt(person.user.id);
});

test('a high score that stays high asks for a code, and passing it cuts the score', async () => {
  const person = await app.signUp('Mia Mfa');
  score(person.user.id, 92);

  // Nothing is asked for while the session is new.
  assert.equal((await person.b('GET', '/api/projects')).status, 200, 'not the moment they land');
  const fresh = await person.b('GET', '/api/me/step-up');
  assert.equal(fresh.body.required, false);

  // Age this session past the dwell, the way two minutes of sitting there would.
  app.db.prepare('UPDATE sessions SET created_at = created_at - ? WHERE user_id = ?')
    .run(MFA.dwellMs + 1000, person.user.id);

  const held = await person.b('GET', '/api/projects');
  assert.equal(held.status, 403);
  assert.equal(held.body.code, 'mfa_required');

  // The step-up itself, /api/me and signing out stay reachable, or there is no way to answer it.
  assert.equal((await person.b('GET', '/api/me/step-up')).body.required, true);
  assert.equal((await person.b('GET', '/api/me')).status, 200);

  const wrong = await person.b('POST', '/api/me/step-up', { code: '000000' });
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.code, 'step_up_failed');
  assert.equal((await person.b('GET', '/api/projects')).status, 403, 'still held');

  const passed = await person.b('POST', '/api/me/step-up', { code: '123456' });
  assert.equal(passed.status, 200, JSON.stringify(passed.body));
  assert.equal(passed.body.status, 'passed');
  assert.equal(passed.body.score, 92 - Math.abs(MFA.discount), 'the discount is applied, not the score rewritten');

  assert.equal((await person.b('GET', '/api/projects')).status, 200, 'and the session carries on');

  // The engine's own measurement is untouched: the discount sits beside it.
  assert.equal(Number(stores.risk.state(person.user.id).score), 92);
  const adjustment = stores.signals.adjustments(person.user.id).find((a) => a.kind === 'mfa_verified');
  assert.equal(adjustment.delta, MFA.discount);
  assert.ok(adjustment.expiresAt, 'and it expires on its own');
});

test('wrong codes run out, and the session stays shut', async () => {
  const person = await app.signUp('Lou Lockout');
  score(person.user.id, 95);
  app.db.prepare('UPDATE sessions SET created_at = created_at - ? WHERE user_id = ?').run(MFA.dwellMs + 1000, person.user.id);
  assert.equal((await person.b('GET', '/api/projects')).body.code, 'mfa_required');

  let last;
  for (let i = 0; i < MFA.maxAttempts; i += 1) last = await person.b('POST', '/api/me/step-up', { code: '999999' });
  assert.equal(last.status, 403);
  assert.equal(last.body.code, 'step_up_locked');

  // Even the right code is too late now.
  const late = await person.b('POST', '/api/me/step-up', { code: '123456' });
  assert.equal(late.status, 403);
  assert.equal((await person.b('GET', '/api/projects')).status, 403);
});

// --- email reputation ---------------------------------------------------------------------------

test('a breached, throwaway address raises the score; a clean one leaves it alone', async () => {
  const person = await app.signUp('Ed Email');
  const canned = async () => ({
    domain: 'mailinator.com', breached: true, breachCount: 3, breaches: ['Dropbox', 'LinkedIn', 'Epik'],
    disposable: true, valid: true, blocked: true, detail: { text: 'Disposable e-mail' },
  });
  const service = createReputationService({ stores, check: canned });

  await service.refresh(person.user);
  const kinds = stores.signals.adjustments(person.user.id).map((a) => a.kind).sort();
  assert.deepEqual(kinds, ['email_breached', 'email_disposable']);
  assert.ok(stores.signals.total(person.user.id) > 0, 'and it raises the effective score');
  assert.equal(service.read(person.user.id).breachCount, 3);

  // A later clean answer withdraws what the first one added, rather than leaving it forever.
  const clean = async () => ({ domain: 'example.com', breached: false, breachCount: 0, breaches: [], disposable: false, valid: true, blocked: false, detail: {} });
  await createReputationService({ stores, check: clean }).refresh(person.user, { force: true });
  assert.deepEqual(stores.signals.adjustments(person.user.id).map((a) => a.kind), []);
});

test('a provider being down is "not checked", never "clean"', async () => {
  const person = await app.signUp('Dee Down');
  const broken = async () => { throw new Error('502'); };
  const service = createReputationService({ stores, check: broken });
  assert.equal(await service.refresh(person.user), null, 'and it never throws at the caller');
  assert.equal(service.read(person.user.id), null, 'nothing was written');

  // The live client turns a failed request into nulls rather than falses.
  const offline = await checkEmail('someone@example.com', { fetchImpl: async () => { throw new Error('offline'); }, key: 'x' });
  assert.equal(offline.breached, null);
  assert.equal(offline.disposable, null);
  assert.equal(offline.valid, null);
});
