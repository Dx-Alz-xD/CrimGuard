'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { PASSWORD, startApp } = require('./helpers');

let app;
before(async () => { app = await startApp(); });
after(() => app.close());

test('pages redirect based on session and role', async () => {
  const anon = app.browser();
  assert.equal((await anon('GET', '/dashboard')).location, '/login');
  assert.equal((await anon('GET', '/admin')).location, '/admin/login');
  assert.equal((await anon('GET', '/admin/login')).status, 200);
  assert.equal((await anon('GET', '/nope')).status, 404);

  const { b } = await app.signUp();
  assert.equal((await b('GET', '/dashboard')).status, 200);
  assert.equal((await b('GET', '/admin')).location, '/dashboard');
  assert.equal((await b('GET', '/login')).location, '/dashboard');

  const admin = await app.signInAdmin();
  assert.equal((await admin.b('GET', '/admin')).status, 200);
  assert.equal((await admin.b('GET', '/dashboard')).location, '/admin');
});

test('writes must be JSON, which blocks cross-site form posts', async () => {
  const { b } = await app.signUp();
  const res = await b('POST', '/api/projects', { name: 'x' }, { 'content-type': 'text/plain' });
  assert.equal(res.status, 415);
});

test('writes from another origin are refused, even with a valid session', async () => {
  const { b } = await app.signUp();
  const evilOrigin = await b('POST', '/api/projects', { name: 'x' }, { origin: 'https://evil.example' });
  assert.equal(evilOrigin.status, 403);
  const nullOrigin = await b('POST', '/api/projects', { name: 'x' }, { origin: 'null' });
  assert.equal(nullOrigin.status, 403);
  const crossSite = await b('POST', '/api/projects', { name: 'x' }, { 'sec-fetch-site': 'cross-site' });
  assert.equal(crossSite.status, 403);
  const sameSite = await b('POST', '/api/projects', { name: 'x' }, { 'sec-fetch-site': 'same-site' });
  assert.equal(sameSite.status, 403);

  const sameOrigin = await b('POST', '/api/projects', { name: 'x' }, { origin: app.base, 'sec-fetch-site': 'same-origin' });
  assert.equal(sameOrigin.status, 201);
  // Behind a proxy that rewrites Host, Origin won't match Host, but the browser still says same-origin.
  const proxied = await b('POST', '/api/projects', { name: 'y' }, { origin: 'https://red.example.com', 'sec-fetch-site': 'same-origin' });
  assert.equal(proxied.status, 201);
  assert.equal((await b('GET', '/api/projects')).body.projects.length, 2, 'only the same-origin writes landed');
});

test('session cookies are HttpOnly and SameSite=Strict, and __Host- prefixed and Secure behind HTTPS', async () => {
  const plain = await app.browser()('POST', '/api/signup', { name: 'Plain', email: app.freshEmail(), password: PASSWORD });
  assert.match(plain.setCookie, /^red_session=/);
  assert.match(plain.setCookie, /HttpOnly/);
  assert.match(plain.setCookie, /SameSite=Strict/);
  assert.match(plain.setCookie, /Path=\//);
  assert.doesNotMatch(plain.setCookie, /Secure|Domain/);

  const httpsHeader = { 'x-forwarded-proto': 'https' };
  const proxied = app.browser();
  const res = await proxied('POST', '/api/signup', { name: 'Proxied', email: app.freshEmail(), password: PASSWORD }, httpsHeader);
  assert.match(res.setCookie, /^__Host-red_session=/);
  assert.match(res.setCookie, /; Secure/);
  assert.equal((await proxied('GET', '/api/me', undefined, httpsHeader)).status, 200);

  // Over HTTPS, a cookie without the prefix (which a subdomain could have planted) is ignored.
  const planted = app.browser();
  planted.useCookie(`red_session=${proxied.getCookie().split('=')[1]}`);
  assert.equal((await planted('GET', '/api/me', undefined, httpsHeader)).status, 401);
});

test('security headers are sent on pages and API responses', async () => {
  const b = app.browser();
  for (const url of ['/', '/api/me']) {
    const { headers } = await b('GET', url);
    assert.match(headers.get('content-security-policy'), /default-src 'none'.*frame-ancestors 'none'/, url);
    assert.equal(headers.get('x-content-type-options'), 'nosniff');
    assert.equal(headers.get('x-frame-options'), 'DENY');
    assert.equal(headers.get('referrer-policy'), 'no-referrer');
    assert.equal(headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.equal(headers.get('strict-transport-security'), null, 'no HSTS over plain HTTP');
  }
  const { headers } = await b('GET', '/', undefined, { 'x-forwarded-proto': 'https' });
  assert.match(headers.get('strict-transport-security'), /max-age=31536000/);
});

test('oversized bodies, wrong methods and bad JSON are rejected cleanly', async () => {
  const { b } = await app.signUp();
  assert.equal((await b('POST', '/api/projects', { name: 'x', description: 'y'.repeat(40_000) })).status, 413);
  const bad = await fetch(`${app.base}/api/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{nope' });
  assert.equal(bad.status, 400);
  const wrongMethod = await b('PUT', '/api/projects', {});
  assert.equal(wrongMethod.status, 405);
  assert.equal((await b('DELETE', '/api/projects')).headers.get('allow'), 'GET, POST');
});

test('health check responds and static files are served', async () => {
  const b = app.browser();
  const health = await b('GET', '/healthz');
  assert.equal(health.status, 200);
  assert.deepEqual(health.body, { ok: true });
  assert.equal((await b('GET', '/static/app.js')).status, 200);
});

test('static paths cannot escape the static folder', async () => {
  // fetch() would normalise "..", so send raw request paths.
  const statusFor = (rawPath) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: app.server.address().port, path: rawPath }, (res) => {
      res.resume();
      resolve(res.statusCode);
    }).on('error', reject);
  });
  assert.equal(await statusFor('/static/../../src/server.js'), 404);
  assert.equal(await statusFor('/static/..%2F..%2Fsrc%2Fapp.js'), 404);
  assert.equal(await statusFor('/static/../../data/pepper.key'), 404);
});

// --- production startup checks ------------------------------------------------------------

function startProduction(env) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'red-test-'));
  try {
    return spawnSync(process.execPath, [path.join(__dirname, '..', 'src', 'server.js')], {
      env: { ...process.env, NODE_ENV: 'production', RED_DB: path.join(dir, 'red.db'), HOST: '127.0.0.1', PORT: '0', RED_PASSWORD_PEPPER: '', RED_ADMIN_PASSWORD: '', ...env },
      encoding: 'utf8',
      timeout: 15_000,
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('in production, Red refuses to start without a password pepper', () => {
  const result = startProduction({ RED_ADMIN_PASSWORD: 'a-long-admin-password' });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /RED_PASSWORD_PEPPER/);
});

test('in production, the first admin is never created with a default password', () => {
  const result = startProduction({ RED_PASSWORD_PEPPER: 'production-pepper-0123456789abcdefghijklmnop' });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /RED_ADMIN_PASSWORD/);
});
