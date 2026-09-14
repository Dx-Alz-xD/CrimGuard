'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { ROOT_DIR } = require('../config');
const { redirect, sendHtml, sendJson, serveStatic } = require('../http/response');
const { isPrivileged } = require('../security/access');
const { homeFor } = require('./auth');
const { isCrawlFile, sendCrawlFile } = require('./crawl');

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

// Handles GET and HEAD for everything outside /api/.
function createPageHandler({ db, sessions, telemetry, trustProxy = false, publicOrigin = null }) {
  const ping = db.prepare('SELECT 1');

  return async function handlePage(req, res, pathname, client = {}) {
    if (pathname === '/healthz') {
      ping.get(); // throws, and so returns 500, if the database is unusable
      return sendJson(res, 200, { ok: true });
    }
    if (pathname.startsWith('/static/')) return serveStatic(res, STATIC_DIR, pathname.slice('/static/'.length));

    if (isCrawlFile(pathname) && sendCrawlFile(req, res, pathname, { trustProxy, configuredOrigin: publicOrigin })) return;

    if (!Object.hasOwn(PAGES, pathname)) {
      return sendHtml(res, 404, await fs.readFile(path.join(PUBLIC_DIR, '404.html')));
    }

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
