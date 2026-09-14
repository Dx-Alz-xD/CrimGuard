'use strict';

// The live console on the CrimGuard dashboard reads the security activity log as it is written.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { startApp } = require('./helpers');

let app;
before(async () => { app = await startApp(); });
after(() => app.close());

test('admins tail the activity log; nobody else can', async () => {
  const person = await app.signUp('Nia Nosy');
  assert.equal((await person.b('GET', '/api/admin/events')).status, 403);
  assert.equal((await app.browser()('GET', '/api/admin/events')).status, 401);

  const admin = await app.signInAdmin();
  const first = await admin.b('GET', '/api/admin/events');
  assert.equal(first.status, 200);
  const ids = first.body.events.map((event) => event.id);
  assert.deepEqual(ids, [...ids].sort((a, b) => a - b), 'oldest first, so the page can append');
  assert.equal(first.body.cursor, ids.at(-1));
  assert.ok(first.body.events.some((event) => event.action === 'account.signup' && event.actor_email === person.email));

  // Nothing new: the cursor stays where it was.
  const quiet = await admin.b('GET', `/api/admin/events?after=${first.body.cursor}`);
  assert.deepEqual([quiet.body.events.length, quiet.body.cursor], [0, first.body.cursor]);

  // Something happens; only that arrives.
  assert.equal((await app.browser()('POST', '/api/login', { email: person.email, password: 'wrong-password-1', portal: 'user' })).status, 401);
  const next = await admin.b('GET', `/api/admin/events?after=${first.body.cursor}`);
  assert.deepEqual(next.body.events.map((event) => event.action), ['login.failed']);
  assert.ok(next.body.cursor > first.body.cursor);

  assert.equal((await admin.b('GET', '/api/admin/events?after=-1')).status, 400);
  assert.equal((await admin.b('GET', '/api/admin/events?after=abc')).status, 400);
});

test('the console only reads: there is no route that takes a command', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'static', 'event-console.js'), 'utf8');
  const calls = [...source.matchAll(/api\('(\w+)'/g)].map((match) => match[1]);
  assert.deepEqual([...new Set(calls)], ['GET'], 'the page only ever GETs');
  assert.doesNotMatch(source, /fetch\(|XMLHttpRequest|sendBeacon/, 'and has no other way to send');
});
