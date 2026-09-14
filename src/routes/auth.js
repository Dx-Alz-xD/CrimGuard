'use strict';

// Sign-up, login, logout, the signed-in account, and changing your own password.

const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson } = require('../http/response');
const { DuplicateEmailError } = require('../db/users');
const { normalizeEmail, personName, requiredEmail, newPassword } = require('../validation');

const homeFor = (user) => (user.role === 'admin' ? '/admin' : '/dashboard');
const publicUser = ({ id, name, email, role }) => ({ id, name, email, role });

function tooManyAttempts(seconds, what = 'attempts') {
  const minutes = Math.max(1, Math.ceil(seconds / 60));
  return new HttpError(429, `Too many ${what}. Try again in ${minutes === 1 ? 'a minute' : `${minutes} minutes`}.`, {
    code: 'rate_limited',
    headers: { 'Retry-After': String(seconds) },
  });
}

// Shared by public sign-up and admins adding a person.
async function createAccount({ users, passwords }, body, { role, mustChangePassword = false }) {
  const name = personName(body.name);
  const email = requiredEmail(body.email);
  const password = newPassword(body.password, { email, name });
  const passwordHash = await passwords.hash(password);
  try {
    return users.create({ name, email, role, passwordHash, mustChangePassword });
  } catch (err) {
    if (err instanceof DuplicateEmailError) throw new HttpError(409, 'An account with that email already exists.');
    throw err;
  }
}

function registerAuthRoutes(router, deps) {
  const { stores, sessions, passwords, throttle, limits, telemetry, protection } = deps;
  const { users, audit } = stores;

  router.post('/api/signup', async ({ req, res, client }) => {
    const ipKey = `signup:ip:${client.ip}`;
    const wait = throttle.retryAfter(ipKey);
    if (wait) throw tooManyAttempts(wait, 'sign-ups from your network');
    // Every attempt counts here, not just failures, to slow down mass account creation.
    throttle.fail(ipKey, limits.signupPerIp);

    const user = await createAccount({ users, passwords }, await readJson(req), { role: 'user' });
    const tokenHash = sessions.start(req, res, user);
    audit.record('account.signup', { actor: user, target: user, ...client });
    telemetry.onLogin({ user, client, tokenHash });
    sendJson(res, 201, { user, redirect: homeFor(user) });
  });

  router.post('/api/login', async ({ req, res, client }) => {
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    const password = typeof body.password === 'string' ? body.password : '';
    const portal = body.portal === 'admin' ? 'admin' : 'user';

    const emailKey = email && `login:email:${email}`;
    const ipKey = `login:ip:${client.ip}`;
    const wait = Math.max(emailKey ? throttle.retryAfter(emailKey) : 0, throttle.retryAfter(ipKey));
    if (wait) throw tooManyAttempts(wait, 'sign-in attempts');

    const row = email ? users.findForLogin(email) : undefined;
    const { valid, needsRehash } = row ? await passwords.verify(password, row.password_hash) : await passwords.verifyDummy(password);

    if (!row || !valid) {
      const blocked = Math.max(emailKey ? throttle.fail(emailKey, limits.loginPerEmail) : 0, throttle.fail(ipKey, limits.loginPerIp));
      // Unknown emails aren't logged: people sometimes type a password into the email field.
      audit.record('login.failed', { target: row ? { id: row.id, email: row.email } : null, ...client, details: { portal, blocked: blocked > 0 } });
      telemetry.onLoginFailure({ userId: row ? row.id : null, client });
      throw new HttpError(401, 'Incorrect email or password.');
    }

    if (portal === 'admin' && row.role !== 'admin') {
      throw new HttpError(403, "This account doesn't have admin access. Use the user login.");
    }
    if (portal === 'user' && row.role === 'admin') {
      throw new HttpError(403, 'This is an admin account. Use the admin login.');
    }

    // A frozen account waits for an admin to restore it (src/identity/), password or not.
    await protection?.assertCanSignIn(row.id);

    if (needsRehash) users.upgradeHash(row.id, await passwords.hash(password), row.password_hash);
    if (emailKey) throttle.reset(emailKey);
    users.recordLogin(row.id);
    const tokenHash = sessions.start(req, res, row);
    audit.record('login.succeeded', { actor: row, target: row, ...client, details: { portal, upgradedHash: needsRehash } });
    telemetry.onLogin({ user: publicUser(row), client, tokenHash });

    sendJson(res, 200, { user: publicUser(row), redirect: homeFor(row), mustChangePassword: row.must_change_password === 1 });
  });

  router.post('/api/logout', async ({ req, res, client }) => {
    const user = sessions.current(req);
    const tokenHash = req.sessionTokenHash;
    sessions.end(req);
    sessions.clearCookie(req, res);
    if (user) {
      audit.record('logout', { actor: user, target: user, ...client });
      telemetry.onLogout({ user, tokenHash, client });
    }
    sendJson(res, 200, { redirect: '/' });
  });

  router.get('/api/me', async ({ req, res }) => {
    sendJson(res, 200, { user: sessions.requireUser(req, { allowPasswordChange: true }) });
  });

  router.patch('/api/me/password', async ({ req, res, client }) => {
    const user = sessions.requireUser(req, { allowPasswordChange: true });
    const body = await readJson(req);
    const key = `password:user:${user.id}`;
    const wait = throttle.retryAfter(key);
    if (wait) throw tooManyAttempts(wait, 'incorrect passwords');

    const newValue = newPassword(body.newPassword, user);
    const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : '';
    // Requiring the current password means someone using a borrowed or stolen session can't lock the owner out.
    const stored = users.passwordHash(user.id);
    if (!stored || !(await passwords.verify(currentPassword, stored)).valid) {
      throttle.fail(key, limits.passwordCheckPerUser);
      audit.record('password.change_failed', { actor: user, target: user, ...client });
      throw new HttpError(400, 'Your current password is incorrect.');
    }
    if (newValue === currentPassword) {
      throw new HttpError(400, 'Choose a new password that is different from your current one.');
    }

    users.setPassword(user.id, await passwords.hash(newValue), { mustChange: false });
    throttle.reset(key);
    telemetry.onPasswordChanged({ user, client, tokenHash: req.sessionTokenHash });
    // A fresh token for this device, and every other device signed out.
    const tokenHash = sessions.start(req, res, user);
    sessions.endOthers(req, user.id);
    audit.record('password.changed', { actor: user, target: user, ...client });
    // The old session is gone, so the new token is what later telemetry belongs to.
    telemetry.onLogin({ user, client, tokenHash });
    sendJson(res, 200, { ok: true });
  });
}

module.exports = { registerAuthRoutes, createAccount, homeFor, publicUser };
