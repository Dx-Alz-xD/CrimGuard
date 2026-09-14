'use strict';

// People, roles and the security activity log, for admins and the CEO. Creating, changing and deleting
// roles is the CEO's alone.

const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson, noContent } = require('../http/response');
const { DuplicateRoleError } = require('../db/roles');
const { MIN_LEVEL, MAX_LEVEL, isLevel, isPrivileged, outranks } = require('../security/access');
const { queueView, requestView } = require('../db/departures');
const { newPassword, singleLine } = require('../validation');
const { createAccount } = require('./auth');

const MAX_SEARCH = 80;

const matches = (user, term) =>
  user.name.toLowerCase().includes(term) || user.email.toLowerCase().includes(term);

function roleFields(body) {
  const label = singleLine(body.label);
  if (!label) throw new HttpError(400, 'Give the role a name.');
  if (label.length > 40) throw new HttpError(400, 'Role names can be up to 40 characters.');
  const clearance = Number(body.clearance);
  if (!isLevel(clearance)) throw new HttpError(400, `Clearance must be a whole number from ${MIN_LEVEL} to ${MAX_LEVEL}.`);
  return { label, clearance };
}

const duplicateRole = (label) => new HttpError(409, `There is already a role called ${label}.`);

const REQUEST_STATUSES = ['pending', 'approved', 'denied'];

function registerAdminRoutes(router, { stores, sessions, passwords, telemetry }) {
  const { users, roles, audit, departures } = stores;

  // A role the actor may hand out: it must exist, and they need at least its clearance. So admins can
  // make someone an intern, employee or admin, and only the CEO can make someone CEO.
  function assignableRole(actor, name) {
    const role = typeof name === 'string' ? roles.byName(name) : null;
    if (!role) throw new HttpError(400, `Choose a role: ${roles.list().map((r) => r.name).join(', ')}.`);
    if (!outranks(actor, role.clearance)) throw new HttpError(403, `Only the CEO can give someone the ${role.label} role.`);
    return role;
  }

  // The account being changed. Nobody can act on an account with more clearance than their own, which
  // keeps a CEO's role, password and account out of an admin's reach.
  function manageableUser(actor, id) {
    const target = users.findById(id);
    if (!target) throw new HttpError(404, 'User not found.');
    if (!outranks(actor, target.clearance)) throw new HttpError(403, 'Only the CEO can change this account.');
    return target;
  }

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
    const role = assignableRole(admin, body.role);
    // The admin knows this password, so the person must replace it when they first sign in.
    const user = await createAccount({ ...stores, passwords }, body, { role: role.name, mustChangePassword: true, actor: admin, client });
    audit.record('admin.user_created', { actor: admin, target: user, ...client, details: { role: role.name } });
    telemetry.onAccountCreated({ actor: admin, tokenHash: req.sessionTokenHash, client, created: user });
    sendJson(res, 201, { user });
  });

  router.patch('/api/admin/users/:id/role', async ({ req, res, params: { id }, client }) => {
    const admin = sessions.requireAdmin(req);
    const body = await readJson(req);
    // Nobody changes their own role, so the last admin or CEO can never lock everyone out.
    if (id === admin.id) throw new HttpError(400, "You can't change your own role.");
    const target = manageableUser(admin, id);
    const role = assignableRole(admin, body.role);
    users.setRole(id, role.name);
    if (target.role !== role.name) {
      audit.record('admin.role_changed', { actor: admin, target, ...client, details: { from: target.role, to: role.name } });
    }
    telemetry.onRoleChanged({
      actor: admin, tokenHash: req.sessionTokenHash, client, target, from: target.role, to: role.name,
    });
    sendJson(res, 200, { user: { ...target, role: role.name, clearance: role.clearance } });
  });

  router.patch('/api/admin/users/:id/password', async ({ req, res, params: { id }, client }) => {
    const admin = sessions.requireAdmin(req);
    const body = await readJson(req);
    const target = manageableUser(admin, id);
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
    // Like the role rule: nobody removes themselves, so an admin and a CEO always remain.
    if (id === admin.id) throw new HttpError(400, "You can't delete your own account. Ask another admin.");
    const target = manageableUser(admin, id);
    if (!users.remove(id)) throw new HttpError(404, 'User not found.');
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

  // ---- access requests from people who are leaving ------------------------------------
  //
  // The gate in routes/files.js refuses the download and the person asks here. Everything needed
  // to decide is in the row: which file, at what level, who is asking, and how long they have left.

  router.get('/api/admin/access-requests', async ({ req, res, url }) => {
    sessions.requireAdmin(req);
    const status = url.searchParams.get('status');
    if (status && !REQUEST_STATUSES.includes(status)) {
      throw new HttpError(400, `Status must be one of: ${REQUEST_STATUSES.join(', ')}.`);
    }
    const requests = departures.list({ status: status || null, limit: 200 });
    sendJson(res, 200, {
      requests: requests.map(queueView),
      pending: departures.pendingCount(),
      leaving: departures.leaving().map((row) => ({
        id: row.user_id, name: row.name, email: row.email, role: row.role, terminationDate: row.termination_date,
      })),
    });
  });

  router.post('/api/admin/access-requests/:id/decision', async ({ req, res, params: { id }, client }) => {
    const actor = sessions.requireAdmin(req);
    const body = await readJson(req);
    if (body.decision !== 'approve' && body.decision !== 'deny') {
      throw new HttpError(400, 'Decide either approve or deny.');
    }
    const existing = departures.byId(id);
    if (!existing) throw new HttpError(404, 'Request not found.');
    if (existing.status !== 'pending') throw new HttpError(409, 'That request has already been decided.');
    // Releasing a file takes the clearance the file itself needs, exactly as changing who can see it
    // does: an admin cannot approve their way into a Secret file.
    if (!outranks(actor, existing.confidentiality)) {
      throw new HttpError(403, `Only the CEO can release a file at level ${existing.confidentiality}.`);
    }

    const note = singleLine(body.note ?? '').slice(0, 300);
    const request = departures.decide(id, { approve: body.decision === 'approve', by: actor, note });
    if (!request) throw new HttpError(409, 'That request has already been decided.');

    const target = users.findById(request.user_id);
    audit.record('file.access_request_decided', {
      actor, target: target || null, ...client,
      details: {
        file: request.file_id, request: request.id, decision: request.status,
        confidentiality: request.confidentiality, expires: request.expires_at,
      },
    });
    telemetry.onPrivilege({
      actor, tokenHash: req.sessionTokenHash, client, type: 'permission_change', targetRedUserId: request.user_id,
      systemName: 'departure-access', details: { file: request.file_id, decision: request.status },
    });
    sendJson(res, 200, { request: requestView(request) });
  });

  // ---- roles --------------------------------------------------------------------------

  // Everyone signed in can read the roles, to show their names and clearances. How many people hold
  // each one is for admins and the CEO.
  router.get('/api/roles', async ({ req, res }) => {
    const user = sessions.requireUser(req);
    const privileged = isPrivileged(user.role);
    const list = roles.list().map(({ member_count: members, ...role }) => (privileged ? { ...role, member_count: members } : role));
    sendJson(res, 200, { roles: list });
  });

  router.post('/api/admin/roles', async ({ req, res, client }) => {
    const ceo = sessions.requireCeo(req);
    const fields = roleFields(await readJson(req));
    let role;
    try {
      role = roles.create(fields);
    } catch (err) {
      if (err instanceof DuplicateRoleError) throw duplicateRole(fields.label);
      throw err;
    }
    audit.record('admin.role_created', { actor: ceo, ...client, details: { role: role.name, label: role.label, clearance: role.clearance } });
    telemetry.onPrivilege({
      actor: ceo, tokenHash: req.sessionTokenHash, client, type: 'permission_change',
      systemName: 'roles', details: { created: role.name, clearance: role.clearance },
    });
    sendJson(res, 201, { role });
  });

  router.patch('/api/admin/roles/:id', async ({ req, res, params: { id }, client }) => {
    const ceo = sessions.requireCeo(req);
    const existing = roles.byId(id);
    if (!existing) throw new HttpError(404, 'Role not found.');
    if (existing.built_in) throw new HttpError(400, `${existing.label} is a built-in role and can't be changed.`);
    const body = await readJson(req);
    const fields = roleFields({
      label: Object.hasOwn(body, 'label') ? body.label : existing.label,
      clearance: Object.hasOwn(body, 'clearance') ? body.clearance : existing.clearance,
    });
    let role;
    try {
      role = roles.update(id, fields);
    } catch (err) {
      if (err instanceof DuplicateRoleError) throw duplicateRole(fields.label);
      throw err;
    }
    if (!role) throw new HttpError(404, 'Role not found.');
    // Raising or lowering a clearance changes which shared files every member can open, so it is logged.
    audit.record('admin.role_updated', {
      actor: ceo, ...client,
      details: { role: role.name, from: { label: existing.label, clearance: existing.clearance }, to: { label: role.label, clearance: role.clearance } },
    });
    telemetry.onPrivilege({
      actor: ceo, tokenHash: req.sessionTokenHash, client, type: 'permission_change',
      systemName: 'roles', details: { updated: role.name, clearance: role.clearance },
    });
    sendJson(res, 200, { role });
  });

  router.delete('/api/admin/roles/:id', async ({ req, res, params: { id }, client }) => {
    const ceo = sessions.requireCeo(req);
    const existing = roles.byId(id);
    if (!existing) throw new HttpError(404, 'Role not found.');
    if (existing.built_in) throw new HttpError(400, `${existing.label} is a built-in role and can't be deleted.`);
    const stillHeld = () => new HttpError(409, `${existing.label} still has people in it. Give them another role first.`);
    if (existing.member_count > 0) throw stillHeld();
    if (!roles.remove(id)) throw stillHeld();
    audit.record('admin.role_deleted', { actor: ceo, ...client, details: { role: existing.name, label: existing.label } });
    telemetry.onPrivilege({
      actor: ceo, tokenHash: req.sessionTokenHash, client, type: 'permission_change',
      systemName: 'roles', details: { deleted: existing.name },
    });
    noContent(res);
  });
}

module.exports = { registerAdminRoutes };
