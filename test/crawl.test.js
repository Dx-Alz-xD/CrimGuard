'use strict';

// robots.txt, sitemap.xml and llms.txt, and the origin they are written against.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { parsePublicOrigin, publicOrigin, validHost } = require('../src/http/origin');
const { redIdOf, externalIdFor } = require('../src/telemetry/subjects');
const { startApp } = require('./helpers');

// fetch() will not send a Host header of our choosing, so these go out through node:http.
function get(base, path, headers = {}) {
  const { hostname, port } = new URL(base);
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname, port, path, headers, method: 'GET' }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('an origin is only built from a host that looks like one', () => {
  assert.equal(validHost('red.example.com'), true);
  assert.equal(validHost('localhost:3000'), true);
  assert.equal(validHost('[::1]:3000'), true);
  for (const bad of ['', 'evil.com/<script>', 'a b', 'evil.com"><x', 'x'.repeat(300)]) {
    assert.equal(validHost(bad), false, bad);
  }

  const req = (headers, encrypted = false) => ({ headers, socket: { encrypted } });
  assert.equal(publicOrigin(req({ host: 'Red.Example.com' })), 'http://red.example.com');
  assert.equal(publicOrigin(req({ host: 'red.example.com' }, true)), 'https://red.example.com');
  assert.equal(publicOrigin(req({ host: 'evil"><x' })), null);
  // Forwarded headers count only behind our own proxy.
  const proxied = req({ host: 'internal:3000', 'x-forwarded-host': 'red.example.com', 'x-forwarded-proto': 'https' });
  assert.equal(publicOrigin(proxied), 'http://internal:3000');
  assert.equal(publicOrigin(proxied, { trustProxy: true }), 'https://red.example.com');
  assert.equal(publicOrigin(proxied, { configured: 'https://red.example.org' }), 'https://red.example.org', 'configured wins');
});

test('RED_PUBLIC_ORIGIN must be a bare origin', () => {
  assert.equal(parsePublicOrigin(''), null);
  assert.equal(parsePublicOrigin('https://red.example.com'), 'https://red.example.com');
  assert.equal(parsePublicOrigin('https://red.example.com/'), 'https://red.example.com');
  for (const bad of ['red.example.com', 'ftp://red.example.com', 'https://red.example.com/app', 'https://u:p@red.example.com', 'https://red.example.com/?q=1']) {
    assert.equal(parsePublicOrigin(bad), undefined, bad);
  }
});

test('a CrimGuard person maps back to a Red account only when they came from Red', () => {
  assert.equal(externalIdFor(12), 'red:12');
  assert.equal(redIdOf('red:12'), 12);
  for (const other of [null, undefined, '', 'okta-00u1abc', 'red:', 'red:honeytoken/3/x', 'red:12x']) {
    assert.equal(redIdOf(other), null, String(other));
  }
});

test('the crawl files list only public pages, against the host that was asked for', async (t) => {
  const app = await startApp();
  t.after(() => app.close());

  const robots = await get(app.base, '/robots.txt', { host: 'red.example.com' });
  assert.equal(robots.status, 200);
  for (const hidden of ['/dashboard', '/admin', '/crimguard', '/api/']) assert.match(robots.body, new RegExp(`^Disallow: ${hidden}$`, 'm'));
  assert.match(robots.body, /^Sitemap: http:\/\/red\.example\.com\/sitemap\.xml$/m);

  const sitemap = await get(app.base, '/sitemap.xml', { host: 'red.example.com' });
  assert.equal(sitemap.status, 200);
  const locs = [...sitemap.body.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  assert.deepEqual(locs, ['/', '/login', '/signup', '/privacy'].map((p) => `http://red.example.com${p}`));
  // Written from one client's Host header, so nothing shared may keep it.
  assert.match(sitemap.headers['cache-control'], /private/);

  const llms = await get(app.base, '/llms.txt', { host: 'red.example.com' });
  assert.match(llms.body, /\(http:\/\/red\.example\.com\/privacy\)/);
});

test('a Host header that is not a host never reaches a sitemap', async (t) => {
  const app = await startApp();
  t.after(() => app.close());

  const sitemap = await get(app.base, '/sitemap.xml', { host: 'evil.test"><script>' });
  assert.equal(sitemap.status, 404);
  assert.doesNotMatch(sitemap.body, /evil/);
  const robots = await get(app.base, '/robots.txt', { host: 'evil.test"><script>' });
  assert.equal(robots.status, 200, 'robots.txt needs no origin to be useful');
  assert.doesNotMatch(robots.body, /evil|Sitemap:/);
});

test('with RED_PUBLIC_ORIGIN set, the crawl files ignore Host and can be cached', async (t) => {
  const app = await startApp({ publicOrigin: 'https://red.example.org' });
  t.after(() => app.close());

  const sitemap = await get(app.base, '/sitemap.xml', { host: 'somewhere-else.test' });
  assert.equal(sitemap.status, 200);
  assert.match(sitemap.body, /<loc>https:\/\/red\.example\.org\/login<\/loc>/);
  assert.doesNotMatch(sitemap.body, /somewhere-else/);
  assert.match(sitemap.headers['cache-control'], /public/);
});

test('every page has a description, public pages a canonical link, and private pages ask not to be indexed', async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const { PAGES } = require('../src/routes/pages');
  const { PUBLIC_PAGES } = require('../src/routes/crawl');
  const publicPaths = new Set(PUBLIC_PAGES.map((page) => page.path));

  for (const [route, file] of [...Object.entries(PAGES), ['(404)', '404.html']]) {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', file), 'utf8');
    assert.match(html, /<meta name="description" content="[^"]{40,}">/, `${file} has a description`);
    assert.equal((html.match(/<title>/g) || []).length, 1, `${file} has one title`);
    if (publicPaths.has(route)) {
      assert.match(html, new RegExp(`<link rel="canonical" href="${route.replace(/\//g, '\\/')}">`), `${file} is canonical at ${route}`);
      assert.doesNotMatch(html, /name="robots" content="noindex/, `${file} is public`);
    } else {
      assert.match(html, /<meta name="robots" content="noindex/, `${file} asks not to be indexed`);
      assert.doesNotMatch(html, /rel="canonical"/, `${file} names no canonical URL`);
    }
    // Every image says what it is, or says it is decoration.
    for (const [img] of html.matchAll(/<img\b[^>]*>/g)) assert.match(img, /\balt="/, `${file}: ${img}`);
    for (const [el] of html.matchAll(/<[a-z]+\b[^>]*role="img"[^>]*>/g)) assert.match(el, /aria-label="[^"]+"/, `${file}: ${el}`);
  }
});
