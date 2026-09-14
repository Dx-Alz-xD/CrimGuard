'use strict';

// People & roles, and the security activity log. Admins only.

const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson, noContent } = require('../http/response');
const { ROLES } = require('../db');
const { newPassword, singleLine } = require('../validation');
const { createAccount } = require('./auth');

const MAX_SEARCH = 80;

const matches = (user, term) =>
  user.name.toLowerCase().includes(term) || user.email.toLowerCase().includes(term);

function registerAdminRoutes(router, { stores, sessions, passwords, telemetry }) {
  const { users, audit } = stores;

  const roleFrom = (body) => {
    if (!ROLES.includes(body.role)) throw new HttpError(400, `Choose a role: ${ROLES.join(' or ')}.`);
    return body.role;
  };

  // Searching happens here rather than in the browser so the terms people look for are
  // visible to the detector behind unusual_search_query_count. The query itself is the only
  // text Red copies into the risk database, truncated, and never tied to anyone's own writing.
  router.get('/api/admin/users', async ({ req, res, url, client }) => {
    const admin = sessions.requireAdmin(req);
    const query = singleLine(url.searchParams.get('q') || '').slice(0, MAX_SEARCH);
    const all = users.list();
    const list = query ? all.filter((user) => matches(user, query.toLowerCase())) : all;

    telemetry.onAccess({
      user: admin, tokenHash: req.sessionTokenHash, client, kind: 'directory', name: 'People directory',
      action: query ? 'search' : 'read', searchQuery: query || null, batch: list.length,
    });
    sendJson(res, 200, { users: list });
  });

  router.post('/api/admin/users', async ({ req, res, client }) => {
    const admin = sessions.requireAdmin(req);
    const body = await readJson(req);
    const role = roleFrom(body);
    // The admin knows this password, so the person must replace it when they first sign in.
    const user = await createAccount({ users, passwords }, body, { role, mustChangePassword: true });
    audit.record('admin.user_created', { actor: admin, target: user, ...client, details: { role } });
    telemetry.onAccountCreated({ actor: admin, tokenHash: req.sessionTokenHash, client, created: user });
    sendJson(res, 201, { user });
  });

  router.patch('/api/admin/users/:id/role', async ({ req, res, params: { id }, client }) => {
    const admin = sessions.requireAdmin(req);
    const role = roleFrom(await readJson(req));
    // Admins can't demote themselves, so the last admin can never lock everyone out.
    if (id === admin.id) throw new HttpError(400, "You can't change your own role. Ask another admin.");
    const target = users.findById(id);
    if (!target) throw new HttpError(404, 'User not found.');
    users.setRole(id, role);
    if (target.role !== role) {
      audit.record('admin.role_changed', { actor: admin, target, ...client, details: { from: target.role, to: role } });
    }
    telemetry.onRoleChanged({
      actor: admin, tokenHash: req.sessionTokenHash, client, target, from: target.role, to: role,
    });
    sendJson(res, 200, { user: { ...target, role } });
  });

  router.patch('/api/admin/users/:id/password', async ({ req, res, params: { id }, client }) => {
    const admin = sessions.requireAdmin(req);
    const body = await readJson(req);
    const target = users.findById(id);
    if (!target) throw new HttpError(404, 'User not found.');
    const password = newPassword(body.password, target);

    const self = id === admin.id;
    if (!users.setPassword(id, await passwords.hash(password), { mustChange: !self })) {
      throw new HttpError(404, 'User not found.');
    }
    // Sign the person out everywhere, so whoever knew the old password loses access now.
    // Admins changing their own password keep the session they're using.
    if (self) sessions.endOthers(req, id);
    else stores.sessions.removeAll(id);
    audit.record('admin.password_reset', { actor: admin, target, ...client });
    telemetry.onPrivilege({
      actor: admin, tokenHash: req.sessionTokenHash, client, type: 'permission_change',
      targetRedUserId: id, systemName: 'password', details: { self },
    });
    if (!self) telemetry.onPasswordChanged({ user: target, client, tokenHash: null });
    sendJson(res, 200, { ok: true });
  });

  router.delete('/api/admin/users/:id', async ({ req, res, params: { id }, client }) => {
    const admin = sessions.requireAdmin(req);
    // Like the role rule: admins can't remove themselves, so an admin always remains.
    if (id === admin.id) throw new HttpError(400, "You can't delete your own account. Ask another admin.");
    const target = users.findById(id);
    if (!target || !users.remove(id)) throw new HttpError(404, 'User not found.');
    audit.record('admin.user_deleted', { actor: admin, target: { id: null, email: target.email }, ...client, details: { role: target.role } });
    telemetry.onPrivilege({
      actor: admin, tokenHash: req.sessionTokenHash, client, type: 'permission_change',
      targetRedUserId: id, systemName: 'account', details: { deleted: true, role: target.role },
    });
    telemetry.onAccountDeleted({ redUserId: id });
    noContent(res);
  });

  router.get('/api/admin/audit', async ({ req, res, url, client }) => {
    const admin = sessions.requireAdmin(req);
    const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 100, 1), 200);
    const before = Number(url.searchParams.get('before')) || null;
    const events = audit.list({ limit, before });
    // The security log is the most sensitive thing in Red, and reading it is worth recording.
    telemetry.onAccess({
      user: admin, tokenHash: req.sessionTokenHash, client, kind: 'audit', name: 'Security activity log',
      action: 'read', batch: events.length,
    });
    sendJson(res, 200, { events, nextBefore: events.length === limit ? events.at(-1).id : null });
  });
}

module.exports = { registerAdminRoutes };
