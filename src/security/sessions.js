'use strict';

const { HttpError } = require('../http/errors');
const { parseCookies, serializeCookie } = require('../http/cookies');
const { isHttps, userAgent } = require('../http/request');
const { newToken, hashToken } = require('./tokens');
const { isPrivileged, isCeo } = require('./access');

// Over HTTPS the cookie uses the __Host- prefix, which browsers only accept with Secure, Path=/ and no
// Domain, so a sibling subdomain can't plant or overwrite it. Plain HTTP (local development) can't use it.
const SECURE_COOKIE = '__Host-red_session';
const PLAIN_COOKIE = 'red_session';

// Only write last_seen_at once a minute, not on every request.
const TOUCH_INTERVAL_MS = 60 * 1000;

function createSessionManager({ sessions, policy, secureCookies, now = Date.now }) {
  const secure = (req) => secureCookies || isHttps(req);
  const cookieName = (req) => (secure(req) ? SECURE_COOKIE : PLAIN_COOKIE);
  // Admins and the CEO get the shorter admin limits; every other role gets the user limits.
  const limitsFor = (role) => (isPrivileged(role) ? policy.admin : policy.user);

  // A request that arrived over HTTPS only trusts the __Host- cookie.
  const tokenFrom = (req) => parseCookies(req.headers.cookie)[cookieName(req)] || null;

  function setCookie(req, res, value, maxAgeMs) {
    res.setHeader('Set-Cookie', serializeCookie(cookieName(req), value, { maxAge: maxAgeMs / 1000, secure: secure(req) }));
  }

  // The signed-in person for this request, or null. Expired sessions are deleted on sight.
  // Limits follow the account's current role, so a promotion to admin also shortens the session.
  function current(req) {
    if (req.sessionUser !== undefined) return req.sessionUser;
    req.sessionUser = null;

    const token = tokenFrom(req);
    if (!token || token.length > 128) return null;
    const tokenHash = hashToken(token);
    const row = sessions.find(tokenHash);
    if (!row) return null;

    const t = now();
    const limits = limitsFor(row.role);
    if (t >= row.expires_at || t - row.created_at >= limits.absoluteMs || t - row.last_seen_at >= limits.idleMs) {
      sessions.remove(tokenHash);
      return null;
    }
    if (t - row.last_seen_at >= TOUCH_INTERVAL_MS) sessions.touch(tokenHash, t);

    req.sessionUser = {
      id: row.id,
      name: row.name,
      email: row.email,
      role: row.role,
      clearance: row.clearance,
      mustChangePassword: row.must_change_password === 1,
    };
    req.sessionTokenHash = tokenHash;
    return req.sessionUser;
  }

  // Issues a new token (never reuses the one the browser sent) and ends the old session.
  function start(req, res, user) {
    end(req);
    const t = now();
    const limits = limitsFor(user.role);
    const token = newToken();
    const tokenHash = hashToken(token);
    sessions.purgeExpired(t);
    sessions.insert({ tokenHash, userId: user.id, now: t, expiresAt: t + limits.absoluteMs, userAgent: userAgent(req) });
    sessions.trim(user.id, policy.maxPerUser);
    setCookie(req, res, token, limits.absoluteMs);
    req.sessionUser = undefined;
    req.sessionTokenHash = tokenHash;
    return tokenHash;
  }

  function end(req) {
    const token = tokenFrom(req);
    if (token) sessions.remove(hashToken(token));
    req.sessionUser = null;
  }

  function clearCookie(req, res) {
    setCookie(req, res, '', 0);
  }

  // Signs the person out everywhere except the session making this request.
  function endOthers(req, userId) {
    sessions.removeOthers(userId, req.sessionTokenHash || '');
  }

  // The hash of a session cookie the browser presented that no longer names a session: a
  // sign-out, an expiry, or a token being replayed. Returns null when the cookie is valid or
  // absent. Call it after current(), which is what removes an expired session.
  function staleTokenHash(req) {
    const token = tokenFrom(req);
    if (!token || token.length > 128) return null;
    const tokenHash = hashToken(token);
    return sessions.find(tokenHash) ? null : tokenHash;
  }

  // allowPasswordChange: the few endpoints someone who must change their password can still use.
  function requireUser(req, { allowPasswordChange = false } = {}) {
    const user = current(req);
    if (!user) throw new HttpError(401, 'Please sign in.');
    if (user.mustChangePassword && !allowPasswordChange) {
      throw new HttpError(403, 'Choose a new password to continue.', { code: 'password_change_required' });
    }
    return user;
  }

  // Admins and the CEO. The code tells the browser this account no longer has the console, rather than
  // that one action was out of reach, so the page can send them back to their dashboard.
  function requireAdmin(req) {
    const user = requireUser(req);
    if (!isPrivileged(user.role)) throw new HttpError(403, 'Admin access required.', { code: 'not_privileged' });
    return user;
  }

  function requireCeo(req) {
    const user = requireAdmin(req);
    if (!isCeo(user.role)) throw new HttpError(403, 'Only the CEO can do this.');
    return user;
  }

  return { current, start, end, endOthers, clearCookie, requireUser, requireAdmin, requireCeo, staleTokenHash };
}

module.exports = { SECURE_COOKIE, PLAIN_COOKIE, createSessionManager };
