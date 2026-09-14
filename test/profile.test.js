'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');

let app;
before(async () => { app = await startApp(); });
after(() => app.close());

test('a new account starts with an empty profile', async () => {
  const { b, email } = await app.signUp('Robin Park');
  const { status, body } = await b('GET', '/api/me/profile');
  assert.equal(status, 200);
  assert.equal(body.profile.name, 'Robin Park');
  assert.equal(body.profile.email, email);
  assert.deepEqual([body.profile.jobTitle, body.profile.organization, body.profile.bio], ['', '', '']);
  assert.ok(!Object.keys(body.profile).some((key) => /hash/i.test(key)));
});

test('people can update their own profile, and a partial update keeps the rest', async () => {
  const { b } = await app.signUp('Robin Park');
  const first = await b('PATCH', '/api/me/profile', { jobTitle: '  Product   designer ', organization: 'Growth', bio: 'Line one\r\nLine two' });
  assert.equal(first.status, 200);
  assert.equal(first.body.profile.jobTitle, 'Product designer');
  assert.equal(first.body.profile.bio, 'Line one\nLine two');

  const second = await b('PATCH', '/api/me/profile', { name: 'Robin P. Park' });
  assert.equal(second.body.profile.name, 'Robin P. Park');
  assert.equal(second.body.profile.organization, 'Growth');
  assert.equal((await b('GET', '/api/me')).body.user.name, 'Robin P. Park', 'the new name shows everywhere');
});

test('profile fields are validated', async () => {
  const { b } = await app.signUp();
  assert.equal((await b('PATCH', '/api/me/profile', { name: '' })).status, 400);
  assert.equal((await b('PATCH', '/api/me/profile', { jobTitle: 'x'.repeat(81) })).status, 400);
  assert.equal((await b('PATCH', '/api/me/profile', { bio: 'x'.repeat(501) })).status, 400);
  assert.equal((await b('PATCH', '/api/me/profile', { email: 'someone-else@red.test' })).status, 200, 'unknown fields are ignored');
  assert.notEqual((await b('GET', '/api/me/profile')).body.profile.email, 'someone-else@red.test');
});

test('profiles are only reachable by their owner', async () => {
  assert.equal((await app.browser()('GET', '/api/me/profile')).status, 401);
  assert.equal((await app.browser()('PATCH', '/api/me/profile', { name: 'Nobody' })).status, 401);
});
