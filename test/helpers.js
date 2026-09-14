'use strict';

const assert = require('node:assert/strict');
const { openDb, ensureAdmin, ensureCeo } = require('../src/db');
const { createApp } = require('../src/app');
const { createPasswordHasher } = require('../src/security/passwords');
const { createProofOfWork, solve } = require('../src/security/proof-of-work');

const PEPPER = 'test-pepper-0123456789abcdefghijklmnopqrstuvwxyz';
const ADMIN = { name: 'Ada Admin', email: 'ada@red.test', password: 'admin-pass-1234' };
const CEO = { name: 'Cleo Chief', email: 'cleo@red.test', password: 'chief-pass-1234' };
const PASSWORD = 'user-pass-1234';

// High enough that ordinary tests never hit them; the rate-limit tests pass their own.
const RELAXED_LIMITS = {
  loginPerEmail: { limit: 1000, windowMs: 60_000, blockMs: 60_000 },
  loginPerIp: { limit: 1000, windowMs: 60_000, blockMs: 60_000 },
  signupPerIp: { limit: 1000, windowMs: 60_000, blockMs: 60_000 },
  passwordCheckPerUser: { limit: 1000, windowMs: 60_000, blockMs: 60_000 },
};

const passwords = createPasswordHasher({ pepper: PEPPER });

// Checks nothing and reaches nobody. Tests that care about reputation build their own with
// createReputationService({ stores, check }) and a canned answer.
const stubReputation = () => ({ enabled: () => false, read: () => null, refresh: async () => null });

// Starts an app on a random port with an in-memory database, one admin and the CEO.
async function startApp(options = {}) {
  const db = options.db || openDb(':memory:');
  await ensureAdmin(db, passwords, ADMIN);
  await ensureCeo(db, passwords, CEO);
  // The real check, at a difficulty that solves instantly: the suite exercises the whole path
  // without spending a second of CPU on every sign-in it makes.
  const proofOfWork = options.proofOfWork ?? createProofOfWork({ baseDifficulty: 4 });
  const server = createApp({
    db, pepper: PEPPER, rateLimits: RELAXED_LIMITS,
    reputation: options.reputation ?? stubReputation(),
    proofOfWork,
    ...options,
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  // A simulated browser with its own cookie jar.
  // Sign-in and sign-up carry a solved challenge. Attached here rather than in every test, so the
  // tests read as what they are about; a test that wants to send a bad one passes its own.
  const NEEDS_PROOF = new Set(['/api/login', '/api/signup']);
  async function proveWork() {
    const res = await fetch(`${base}/api/auth/challenge`);
    const { required, challenge, difficulty } = await res.json();
    return required ? { challenge, solution: solve(challenge, difficulty) } : {};
  }

  function browser() {
    let cookie = '';
    const call = async (method, url, body, headers = {}) => {
      if (method === 'POST' && NEEDS_PROOF.has(url) && body && !body.challenge) {
        body = { ...body, ...(await proveWork()) };
      }
      const res = await fetch(base + url, {
        method,
        redirect: 'manual',
        headers: {
          ...(cookie ? { cookie } : {}),
          ...(method === 'GET' ? {} : { 'content-type': 'application/json' }),
          ...headers,
        },
        body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
      });
      const setCookie = res.headers.get('set-cookie');
      if (setCookie) cookie = setCookie.split(';')[0];
      const isJson = (res.headers.get('content-type') || '').includes('application/json');
      return {
        status: res.status,
        headers: res.headers,
        location: res.headers.get('location'),
        setCookie,
        body: isJson ? await res.json() : await res.text(),
      };
    };
    call.getCookie = () => cookie;
    call.useCookie = (value) => { cookie = value; };
    return call;
  }

  let emailCounter = 0;
  const freshEmail = () => `person${++emailCounter}-${Math.random().toString(36).slice(2, 8)}@red.test`;

  async function signUp(name = 'Test User') {
    const b = browser();
    const email = freshEmail();
    const res = await b('POST', '/api/signup', { name, email, password: PASSWORD });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    return { b, email, user: res.body.user };
  }

  async function signInAs({ email, password }) {
    const b = browser();
    const res = await b('POST', '/api/login', { email, password, portal: 'admin' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    return { b, user: res.body.user };
  }
  const signInAdmin = () => signInAs(ADMIN);
  const signInCeo = () => signInAs(CEO);

  // Signs someone up (as an intern) and has the CEO give them another role. The CEO's session is
  // reused across calls, and replaced if a test has ended it.
  let chief = null;
  async function signUpAs(role, name) {
    const person = await signUp(name);
    if (role === 'intern') return person;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      chief = chief || (await signInCeo());
      const res = await chief.b('PATCH', `/api/admin/users/${person.user.id}/role`, { role });
      if (res.status === 401) {
        chief = null;
        continue;
      }
      assert.equal(res.status, 200, JSON.stringify(res.body));
      person.user = res.body.user;
      return person;
    }
    throw new Error('Could not sign in as the CEO.');
  }

  function close() {
    server.closeAllConnections();
    server.close();
  }

  return { db, server, base, browser, proveWork, freshEmail, signUp, signUpAs, signInAdmin, signInCeo, close };
}

module.exports = { PEPPER, ADMIN, CEO, PASSWORD, RELAXED_LIMITS, passwords, stubReputation, startApp };
