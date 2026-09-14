'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { ROOT_DIR } = require('../config');
const { redirect, sendHtml, sendJson, serveStatic } = require('../http/response');
const { isPrivileged } = require('../security/access');
const { homeFor } = require('./auth');

const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const STATIC_DIR = path.join(PUBLIC_DIR, 'static');

const PAGES = {
  '/': 'index.html',
  '/login': 'login.html',
  '/admin/login': 'admin-login.html',
  '/signup': 'signup.html',
  '/dashboard': 'dashboard.html',
  '/admin': 'admin.html',
  '/admin/risk': 'risk.html',
  '/crimguard': 'crimguard.html',
  '/privacy': 'privacy.html',
};

// Pages only admins and the CEO can open, and so count as admin_panel_access.
const ADMIN_PAGES = new Set(['/admin', '/admin/risk', '/crimguard']);

const NOT_FOUND_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark">
<title>Not found · Red</title><link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,100..900&display=swap">
<link rel="stylesheet" href="/static/styles.css"></head>
<body><main class="notfound"><a class="wordmark" href="/"><span class="wordmark-mark" aria-hidden="true"></span>Red</a>
<h1>This page doesn't exist</h1><p>Check the address, or go back to the start.</p>
<a class="btn btn-primary" href="/">Go to Red</a></main></body></html>`;

// Where a page request should go instead, given who is signed in. null means serve the page.
function pageRedirect(pathname, user) {
  switch (pathname) {
    case '/':
    case '/login':
    case '/signup':
      return user ? homeFor(user) : null;
    case '/admin/login':
      return user && isPrivileged(user.role) ? '/admin' : null;
    case '/dashboard':
      if (!user) return '/login';
      return isPrivileged(user.role) ? '/admin' : null;
    case '/admin':
    case '/admin/risk':
    case '/crimguard':
      if (!user) return '/admin/login';
      return isPrivileged(user.role) ? null : '/dashboard';
    default:
      return null;
  }
}

// Handles GET and HEAD for everything outside /api/. Returns false if the path isn't ours.
function createPageHandler({ db, sessions, telemetry }) {
  const ping = db.prepare('SELECT 1');

  return async function handlePage(req, res, pathname, client = {}) {
    if (pathname === '/healthz') {
      ping.get(); // throws, and so returns 500, if the database is unusable
      return sendJson(res, 200, { ok: true });
    }
    if (pathname.startsWith('/static/')) return serveStatic(res, STATIC_DIR, pathname.slice('/static/'.length));
    if (!Object.hasOwn(PAGES, pathname)) return sendHtml(res, 404, NOT_FOUND_HTML);

    const user = sessions.current(req);
    const target = pageRedirect(pathname, user);
    if (target) return redirect(res, target);

    if (user) {
      telemetry.onAccess({
        user, tokenHash: req.sessionTokenHash, client, kind: 'page', id: pathname.slice(1) || 'home',
        name: pathname, action: 'read',
      });
      if (ADMIN_PAGES.has(pathname)) {
        telemetry.onPrivilege({ actor: user, tokenHash: req.sessionTokenHash, client, type: 'admin_panel_access', systemName: pathname });
      }
    }
    return sendHtml(res, 200, await fs.readFile(path.join(PUBLIC_DIR, PAGES[pathname])));
  };
}

module.exports = { PAGES, ADMIN_PAGES, PUBLIC_DIR, createPageHandler, pageRedirect };
