'use strict';

// The scripts under public/static/ are only ever run by a browser, so nothing else in the
// test suite would notice a syntax error in them - the page would simply stop working. These
// checks parse each one the way the browser will.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { PUBLIC_DIR, PAGES } = require('../src/routes/pages');

const STATIC_DIR = path.join(PUBLIC_DIR, 'static');
const scripts = fs.readdirSync(STATIC_DIR).filter((file) => file.endsWith('.js'));

test('every client script parses', () => {
  assert.ok(scripts.length >= 4, 'there are client scripts to check');
  for (const file of scripts) {
    const source = fs.readFileSync(path.join(STATIC_DIR, file), 'utf8');
    // Compiling is enough: it parses exactly as a browser would, without running anything.
    assert.doesNotThrow(() => new vm.Script(source, { filename: file }), file);
  }
});

test('every script and stylesheet a page asks for exists', () => {
  for (const file of Object.values(PAGES)) {
    const html = fs.readFileSync(path.join(PUBLIC_DIR, file), 'utf8');
    for (const [, src] of html.matchAll(/<script src="\/static\/([^"]+)"/g)) {
      assert.ok(fs.existsSync(path.join(STATIC_DIR, src)), `${file} asks for /static/${src}`);
    }
    for (const [, href] of html.matchAll(/<link[^>]+href="\/static\/([^"]+)"/g)) {
      assert.ok(fs.existsSync(path.join(STATIC_DIR, href)), `${file} asks for /static/${href}`);
    }
  }
});

test('the signed-in pages load the collector and the risk panel', () => {
  for (const page of ['dashboard.html', 'admin.html', 'risk.html']) {
    const html = fs.readFileSync(path.join(PUBLIC_DIR, page), 'utf8');
    assert.match(html, /<script src="\/static\/telemetry\.js">/, page);
    assert.match(html, /<script src="\/static\/risk-panel\.js">/, page);
  }
  // The signed-out pages must not: there is no session to attribute anything to.
  for (const page of ['index.html', 'login.html', 'signup.html', 'admin-login.html']) {
    const html = fs.readFileSync(path.join(PUBLIC_DIR, page), 'utf8');
    assert.doesNotMatch(html, /telemetry\.js/, page);
  }
});

test('the collector never sends anything it should not', () => {
  const source = fs.readFileSync(path.join(STATIC_DIR, 'telemetry.js'), 'utf8');
  // Key identity is read only to spot Print Screen, and must never reach the payload.
  const body = source.slice(source.indexOf('function send('));
  for (const forbidden of ['event.key', 'clientX', 'clientY', 'getSelection()', 'innerText']) {
    assert.ok(!body.includes(forbidden), `send() must not reach for ${forbidden}`);
  }
  // What it does send is the aggregate shape the ingest endpoint validates.
  assert.match(source, /samples: pending\.splice/);
  assert.match(source, /device: device\(\)/);
});
