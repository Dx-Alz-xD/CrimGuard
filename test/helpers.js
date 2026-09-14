'use strict';

const assert = require('node:assert/strict');
const { openDb, ensureAdmin } = require('../src/db');
const { createApp } = require('../src/app');
const { createPasswordHasher } = require('../src/security/passwords');

const PEPPER = 'test-pepper-0123456789abcdefghijklmnopqrstuvwxyz';
const ADMIN = { name: 'Ada Admin', email: 'ada@red.test', password: 'admin-pass-1234' };
const PASSWORD = 'user-pass-1234';

// High enough that ordinary tests never hit them; the rate-limit tests pass their own.
const RELAXED_LIMITS = {
  loginPerEmail: { limit: 1000, windowMs: 60_000, blockMs: 60_000 },
  loginPerIp: { limit: 1000, windowMs: 60_000, blockMs: 60_000 },
  signupPerIp: { limit: 1000, windowMs: 60_000, blockMs: 60_000 },
  passwordCheckPerUser: { limit: 1000, windowMs: 60_000, blockMs: 60_000 },
};

const passwords = createPasswordHasher({ pepper: PEPPER });

// Starts an app on a random port with an in-memory database and one admin.
async function startApp(options = {}) {
  const db = options.db || openDb(':memory:');
  await ensureAdmin(db, passwords, ADMIN);
  const server = createApp({ db, pepper: PEPPER, rateLimits: RELAXED_LIMITS, ...options });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  // A simulated browser with its own cookie jar.
  function browser() {
    let cookie = '';
    const call = async (method, url, body, headers = {}) => {
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

  async function signInAdmin() {
    const b = browser();
    const res = await b('POST', '/api/login', { email: ADMIN.email, password: ADMIN.password, portal: 'admin' });
    assert.equal(res.status, 200, JSON.stringify(res.body));
    return { b, user: res.body.user };
  }

  function close() {
    server.closeAllConnections();
    server.close();
  }

  return { db, server, base, browser, freshEmail, signUp, signInAdmin, close };
}

module.exports = { PEPPER, ADMIN, PASSWORD, RELAXED_LIMITS, passwords, startApp };
