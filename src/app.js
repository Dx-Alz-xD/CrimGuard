'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const auth = require('./auth');
const { ROLES, STATUSES } = require('./db');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const STATIC_DIR = path.join(PUBLIC_DIR, 'static');
const SESSION_COOKIE = 'red_session';
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_BODY_BYTES = 64 * 1024;

const PAGES = {
  '/': 'index.html',
  '/login': 'login.html',
  '/admin/login': 'admin-login.html',
  '/signup': 'signup.html',
  '/dashboard': 'dashboard.html',
  '/admin': 'admin.html',
};

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
};

const SECURITY_HEADERS = {
  // Google Fonts serves the Archivo stylesheet and font files; everything else stays same-origin.
  'Content-Security-Policy': "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
};

const NOT_FOUND_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark">
<title>Not found · Red</title><link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,100..900&display=swap">
<link rel="stylesheet" href="/static/styles.css"></head>
<body><main class="notfound"><a class="wordmark" href="/"><span class="wordmark-mark" aria-hidden="true"></span>Red</a>
<h1>This page doesn't exist</h1><p>Check the address, or go back to the start.</p>
<a class="btn btn-primary" href="/">Go to Red</a></main></body></html>`;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const homeFor = (user) => (user.role === 'admin' ? '/admin' : '/dashboard');

const publicUser = ({ id, name, email, role }) => ({ id, name, email, role });

// Where a page request should go instead, given who is signed in. null means serve the page.
function pageRedirect(pathname, user) {
  switch (pathname) {
    case '/':
    case '/login':
    case '/signup':
      return user ? homeFor(user) : null;
    case '/admin/login':
      return user?.role === 'admin' ? '/admin' : null;
    case '/dashboard':
      if (!user) return '/login';
      return user.role === 'admin' ? '/admin' : null;
    case '/admin':
      if (!user) return '/admin/login';
      return user.role === 'admin' ? null : '/dashboard';
    default:
      return null;
  }
}

// Hosting platforms terminate TLS at a proxy and forward plain HTTP, so also honour
// X-Forwarded-Proto. A spoofed header can only add the Secure flag, which weakens nothing.
const isHttps = (req) =>
  Boolean(req.socket.encrypted) || String(req.headers['x-forwarded-proto']).split(',')[0].trim() === 'https';

function normalizeEmail(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : '';
}

const singleLine = (value) => (typeof value === 'string' ? value.replace(/\s+/g, ' ').trim() : '');

function validPassword(value) {
  const password = typeof value === 'string' ? value : '';
  if (password.length < 8 || password.length > 200) throw new HttpError(400, 'Password must be 8 to 200 characters.');
  return password;
}

// Validates a create (no `current`) or a partial update merged over `current`.
function projectFields(body, current = { name: '', description: '', status: 'planning' }) {
  const name = Object.hasOwn(body, 'name') ? singleLine(body.name) : current.name;
  const description = Object.hasOwn(body, 'description')
    ? (typeof body.description === 'string' ? body.description.trim() : '')
    : current.description;
  const status = Object.hasOwn(body, 'status') ? body.status : current.status;

  if (!name) throw new HttpError(400, 'Project name is required.');
  if (name.length > 120) throw new HttpError(400, 'Project name must be 120 characters or fewer.');
  if (description.length > 2000) throw new HttpError(400, 'Description must be 2000 characters or fewer.');
  if (!STATUSES.includes(status)) throw new HttpError(400, `Status must be one of: ${STATUSES.join(', ')}.`);
  return { name, description, status };
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Request body is too large.');
    chunks.push(chunk);
  }
  if (size === 0) return {};

  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Request body is not valid JSON.');
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'Expected a JSON object.');
  return body;
}

function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}

async function serveStatic(res, relative) {
  const file = path.resolve(STATIC_DIR, relative);
  const type = MIME_TYPES[path.extname(file)];
  if (!file.startsWith(STATIC_DIR + path.sep) || !type) throw new HttpError(404, 'Not found.');

  let data;
  try {
    data = await fs.readFile(file);
  } catch (err) {
    if (err.code === 'ENOENT' || err.code === 'EISDIR') throw new HttpError(404, 'Not found.');
    throw err;
  }
  res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache' });
  res.end(data);
}

function createApp({ db, secureCookies = false }) {
  const q = {
    ping: db.prepare('SELECT 1'),
    userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
    userById: db.prepare('SELECT id, name, email, role FROM users WHERE id = ?'),
    insertUser: db.prepare('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)'),
    setRole: db.prepare('UPDATE users SET role = ? WHERE id = ?'),
    setPassword: db.prepare('UPDATE users SET password_hash = ? WHERE id = ?'),
    passwordHashById: db.prepare('SELECT password_hash FROM users WHERE id = ?'),
    // The account's projects and sessions go with it (ON DELETE CASCADE).
    deleteUser: db.prepare('DELETE FROM users WHERE id = ?'),
    listUsers: db.prepare(`
      SELECT u.id, u.name, u.email, u.role, u.created_at, COUNT(p.id) AS project_count
      FROM users u LEFT JOIN projects p ON p.owner_id = u.id
      GROUP BY u.id
      ORDER BY u.created_at, u.id`),

    // Role is read from the users table on every request, so a role change applies
    // to sessions that are already open.
    sessionUser: db.prepare(`
      SELECT u.id, u.name, u.email, u.role
      FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ? AND s.expires_at > ?`),
    insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)'),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    deleteOtherSessions: db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?'),
    purgeExpiredSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),

    // Every project query is scoped by owner_id: another account's project is indistinguishable from a missing one.
    listProjects: db.prepare(`
      SELECT id, name, description, status, created_at, updated_at
      FROM projects WHERE owner_id = ?
      ORDER BY updated_at DESC, id DESC`),
    getProject: db.prepare(`
      SELECT id, name, description, status, created_at, updated_at
      FROM projects WHERE id = ? AND owner_id = ?`),
    insertProject: db.prepare('INSERT INTO projects (owner_id, name, description, status) VALUES (?, ?, ?, ?)'),
    updateProject: db.prepare(`
      UPDATE projects SET name = ?, description = ?, status = ?, updated_at = datetime('now')
      WHERE id = ? AND owner_id = ?`),
    deleteProject: db.prepare('DELETE FROM projects WHERE id = ? AND owner_id = ?'),
  };

  // --- sessions -------------------------------------------------------------

  const sessionToken = (req) => auth.parseCookies(req.headers.cookie)[SESSION_COOKIE] || null;

  function currentUser(req) {
    const token = sessionToken(req);
    return (token && q.sessionUser.get(auth.hashToken(token), Date.now())) || null;
  }

  function setSessionCookie(req, res, value, maxAgeSeconds) {
    const attributes = [`${SESSION_COOKIE}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSeconds}`];
    if (secureCookies || isHttps(req)) attributes.push('Secure');
    res.setHeader('Set-Cookie', attributes.join('; '));
  }

  function endSession(req) {
    const token = sessionToken(req);
    if (token) q.deleteSession.run(auth.hashToken(token));
  }

  function startSession(req, res, userId) {
    endSession(req);
    q.purgeExpiredSessions.run(Date.now());
    const token = auth.newToken();
    q.insertSession.run(auth.hashToken(token), userId, Date.now() + SESSION_TTL_SECONDS * 1000);
    setSessionCookie(req, res, token, SESSION_TTL_SECONDS);
  }

  function requireUser(req) {
    const user = currentUser(req);
    if (!user) throw new HttpError(401, 'Please sign in.');
    return user;
  }

  function requireAdmin(req) {
    const user = requireUser(req);
    if (user.role !== 'admin') throw new HttpError(403, 'Admin access required.');
    return user;
  }

  // --- accounts -------------------------------------------------------------

  // Shared by public sign-up (always role "user") and admins adding a person with a chosen role.
  async function createAccount(body, role) {
    const name = singleLine(body.name);
    const email = normalizeEmail(body.email);

    if (!name || name.length > 80) throw new HttpError(400, 'Enter a name (up to 80 characters).');
    if (!email) throw new HttpError(400, 'Enter a valid email address.');
    const password = validPassword(body.password);

    const passwordHash = await auth.hashPassword(password);
    try {
      const { lastInsertRowid } = q.insertUser.run(name, email, passwordHash, role);
      return { id: Number(lastInsertRowid), name, email, role };
    } catch (err) {
      if (/UNIQUE constraint failed/.test(err.message)) throw new HttpError(409, 'An account with that email already exists.');
      throw err;
    }
  }

  async function signup(req, res) {
    const user = await createAccount(await readJson(req), 'user');
    startSession(req, res, user.id);
    sendJson(res, 201, { user, redirect: homeFor(user) });
  }

  async function login(req, res) {
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    const password = typeof body.password === 'string' ? body.password : '';
    const portal = body.portal === 'admin' ? 'admin' : 'user';

    const row = email ? q.userByEmail.get(email) : undefined;
    const valid = await auth.verifyPassword(password, row ? row.password_hash : auth.DUMMY_HASH);
    if (!row || !valid) throw new HttpError(401, 'Incorrect email or password.');

    if (portal === 'admin' && row.role !== 'admin') {
      throw new HttpError(403, "This account doesn't have admin access. Use the user login.");
    }
    if (portal === 'user' && row.role === 'admin') {
      throw new HttpError(403, 'This is an admin account. Use the admin login.');
    }

    startSession(req, res, row.id);
    sendJson(res, 200, { user: publicUser(row), redirect: homeFor(row) });
  }

  // --- routing --------------------------------------------------------------

  async function handleApi(req, res, pathname) {
    const { method } = req;

    // A cross-site page can't send application/json without a CORS preflight, which this
    // server never grants. Together with SameSite=Strict cookies, that blocks CSRF.
    if (method !== 'GET' && !String(req.headers['content-type']).startsWith('application/json')) {
      throw new HttpError(415, 'Requests must be sent as JSON.');
    }

    const id = Number(pathname.match(/\/(\d{1,15})(?:\/|$)/)?.[1]);
    const routeKey = `${method} ${pathname.replace(/\/\d{1,15}(?=\/|$)/, '/:id')}`;

    switch (routeKey) {
      case 'POST /api/signup':
        return signup(req, res);
      case 'POST /api/login':
        return login(req, res);
      case 'POST /api/logout':
        endSession(req);
        setSessionCookie(req, res, '', 0);
        return sendJson(res, 200, { redirect: '/' });
      case 'GET /api/me':
        return sendJson(res, 200, { user: requireUser(req) });

      case 'PATCH /api/me/password': {
        const user = requireUser(req);
        const body = await readJson(req);
        const newPassword = validPassword(body.newPassword);
        const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : '';
        const row = q.passwordHashById.get(user.id);
        // Requiring the current password means someone using a borrowed or stolen session can't lock the owner out.
        if (!row || !(await auth.verifyPassword(currentPassword, row.password_hash))) {
          throw new HttpError(400, 'Your current password is incorrect.');
        }
        if (newPassword === currentPassword) {
          throw new HttpError(400, 'Choose a new password that is different from your current one.');
        }
        q.setPassword.run(await auth.hashPassword(newPassword), user.id);
        // Stay signed in on this device; sign out everywhere else.
        q.deleteOtherSessions.run(user.id, auth.hashToken(sessionToken(req)));
        return sendJson(res, 200, { ok: true });
      }

      case 'GET /api/projects':
        return sendJson(res, 200, { projects: q.listProjects.all(requireUser(req).id) });

      case 'POST /api/projects': {
        const user = requireUser(req);
        const fields = projectFields(await readJson(req));
        const { lastInsertRowid } = q.insertProject.run(user.id, fields.name, fields.description, fields.status);
        return sendJson(res, 201, { project: q.getProject.get(lastInsertRowid, user.id) });
      }

      case 'PATCH /api/projects/:id': {
        const user = requireUser(req);
        const existing = q.getProject.get(id, user.id);
        if (!existing) throw new HttpError(404, 'Project not found.');
        const fields = projectFields(await readJson(req), existing);
        q.updateProject.run(fields.name, fields.description, fields.status, id, user.id);
        return sendJson(res, 200, { project: q.getProject.get(id, user.id) });
      }

      case 'DELETE /api/projects/:id': {
        const user = requireUser(req);
        if (q.deleteProject.run(id, user.id).changes === 0) throw new HttpError(404, 'Project not found.');
        res.writeHead(204);
        return res.end();
      }

      case 'GET /api/admin/users':
        requireAdmin(req);
        return sendJson(res, 200, { users: q.listUsers.all() });

      case 'POST /api/admin/users': {
        requireAdmin(req);
        const body = await readJson(req);
        if (!ROLES.includes(body.role)) throw new HttpError(400, `Choose a role: ${ROLES.join(' or ')}.`);
        return sendJson(res, 201, { user: await createAccount(body, body.role) });
      }

      case 'PATCH /api/admin/users/:id/role': {
        const admin = requireAdmin(req);
        const { role } = await readJson(req);
        if (!ROLES.includes(role)) throw new HttpError(400, `Choose a role: ${ROLES.join(' or ')}.`);
        // Admins can't demote themselves, so the last admin can never lock everyone out.
        if (id === admin.id) throw new HttpError(400, "You can't change your own role. Ask another admin.");
        const target = q.userById.get(id);
        if (!target) throw new HttpError(404, 'User not found.');
        q.setRole.run(role, id);
        return sendJson(res, 200, { user: { ...target, role } });
      }

      case 'PATCH /api/admin/users/:id/password': {
        const admin = requireAdmin(req);
        const password = validPassword((await readJson(req)).password);
        if (!q.userById.get(id)) throw new HttpError(404, 'User not found.');
        const passwordHash = await auth.hashPassword(password);
        if (q.setPassword.run(passwordHash, id).changes === 0) throw new HttpError(404, 'User not found.');
        // Sign the person out everywhere, so whoever knew the old password loses access now.
        // Admins changing their own password keep the session they're using.
        q.deleteOtherSessions.run(id, id === admin.id ? auth.hashToken(sessionToken(req)) : '');
        return sendJson(res, 200, { ok: true });
      }

      case 'DELETE /api/admin/users/:id': {
        const admin = requireAdmin(req);
        // Like the role rule: admins can't remove themselves, so an admin always remains.
        if (id === admin.id) throw new HttpError(400, "You can't delete your own account. Ask another admin.");
        if (q.deleteUser.run(id).changes === 0) throw new HttpError(404, 'User not found.');
        res.writeHead(204);
        return res.end();
      }

      default:
        throw new HttpError(404, 'Not found.');
    }
  }

  async function route(req, res) {
    const rawPath = new URL(req.url, 'http://red.local').pathname;
    const pathname = rawPath.length > 1 ? rawPath.replace(/\/+$/, '') : rawPath;

    if (pathname.startsWith('/api/')) return handleApi(req, res, pathname);
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed.');

    if (pathname === '/healthz') {
      q.ping.get(); // throws, and so returns 500, if the database is unusable
      return sendJson(res, 200, { ok: true });
    }
    if (pathname.startsWith('/static/')) return serveStatic(res, pathname.slice('/static/'.length));

    if (!Object.hasOwn(PAGES, pathname)) {
      res.writeHead(404, { 'Content-Type': MIME_TYPES['.html'] });
      return res.end(NOT_FOUND_HTML);
    }

    const target = pageRedirect(pathname, currentUser(req));
    if (target) {
      res.writeHead(302, { Location: target, 'Cache-Control': 'no-store' });
      return res.end();
    }

    const html = await fs.readFile(path.join(PUBLIC_DIR, PAGES[pathname]));
    res.writeHead(200, { 'Content-Type': MIME_TYPES['.html'], 'Cache-Control': 'no-store' });
    res.end(html);
  }

  return http.createServer((req, res) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(name, value);
    route(req, res).catch((err) => {
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) console.error(err);
      if (res.headersSent) return res.destroy();
      sendJson(res, status, { error: status === 500 ? 'Something went wrong.' : err.message });
    });
  });
}

module.exports = { createApp };
