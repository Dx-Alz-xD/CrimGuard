'use strict';

const { DuplicateFileNameError } = require('../db/files');
const { HttpError } = require('../http/errors');
const { readJson, readBinary } = require('../http/request');
const { sendJson, noContent } = require('../http/response');
const { CONFIDENTIALITY, MIN_LEVEL, MAX_LEVEL, canManageFileAccess, isLevel, isPrivileged, outranks } = require('../security/access');
const { isDecoyId } = require('../telemetry/honeytokens');
const { singleLine } = require('../validation');

// How many roles and people one file can be shared with in a single save.
const MAX_ROLE_GRANTS = 50;
const MAX_PEOPLE_GRANTS = 500;

// The name as it will be shown: only the last path segment, at most 255 characters.
// singleLine also removes control and bidirectional characters and tidies whitespace.
function fileName(value) {
  const name = singleLine(typeof value === 'string' ? value.split(/[\\/]/).pop() : '');
  if (!name || name === '.' || name === '..') throw new HttpError(400, 'Give the file a name.');
  if (name.length > 255) throw new HttpError(400, 'File names can be up to 255 characters.');
  return name;
}

// Upload names travel URL-encoded in the X-File-Name header, which can't carry most non-ASCII text as-is.
function fileNameFromHeader(value) {
  let decoded;
  try {
    decoded = decodeURIComponent(String(value ?? ''));
  } catch {
    throw new HttpError(400, 'The file name could not be read.');
  }
  return fileName(decoded);
}

// Only used to label the file in the list. Downloads are always sent as application/octet-stream.
function fileType(value) {
  const type = String(value ?? '').trim().toLowerCase();
  return type.length <= 100 && /^[a-z0-9][\w!#$&^.+-]*\/[a-z0-9][\w!#$&^.+-]*$/.test(type) ? type : 'application/octet-stream';
}

function contentDisposition(name) {
  // Plain filename= for old clients: anything outside printable ASCII, and quotes or backslashes, become "_".
  const fallback = Array.from(name, (char) => {
    const code = char.codePointAt(0);
    return code < 32 || code > 126 || code === 34 || code === 92 ? '_' : char;
  }).join('');
  const encoded = encodeURIComponent(name).replace(/['()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
  return `attachment; filename="${fallback}"; filename*=UTF-8''${encoded}`;
}

// Always a download, with a generic type and a sandbox policy: an uploaded HTML or SVG file must never
// render or run on this origin.
function sendDownload(res, name, content) {
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': content.byteLength,
    'Content-Disposition': contentDisposition(name),
    'Content-Security-Policy': "default-src 'none'; sandbox",
    'Cache-Control': 'private, no-store',
  });
  res.end(content);
}

const duplicateName = (name) =>
  new HttpError(409, `A file named "${name}" is already in this project. Rename one of them, or replace the existing file.`);
const fileNotFound = () => new HttpError(404, 'File not found.');

// A list of ids from the access dialog: whole numbers, each once.
function idList(value, what, max) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > max || !value.every((id) => Number.isInteger(id) && id > 0)) {
    throw new HttpError(400, `${what} must be a list of up to ${max} ids.`);
  }
  return [...new Set(value)];
}

function registerFileRoutes(router, { stores, sessions, telemetry, maxFileBytes, protection }) {
  const { projects, files, roles, users, audit } = stores;

  function ownProject(user, projectId) {
    const project = projects.get(projectId, user.id);
    if (!project) throw new HttpError(404, 'Project not found.');
    return project;
  }

  // Decoy projects (telemetry/honeytokens.js) sit in a risky account's project list. Opening one must
  // look like opening an empty project. Changing one is the trip, handled exactly as routes/projects.js
  // does: record it, revoke every session the account has, and answer as a signed-out request.
  // trip() returns null unless a live decoy with this id was planted for this very account; the request
  // then carries on and gets the ordinary "not found".
  async function springTrap({ req, user, id, client }) {
    const report = await telemetry.honeytokens.trip({
      user, decoyId: id, interaction: 'modified', client, tokenHash: req.sessionTokenHash,
    });
    if (!report) return;

    stores.sessions.removeAll(user.id);
    stores.audit.record('security.honeytoken_tripped', {
      actor: user, target: user, ...client, details: { interaction: 'modified', decoy: report.decoy, score: report.score },
    });
    // The identity throttle turns it into a freeze: signing back in waits for an admin.
    await protection?.onHoneytokenTrip(report);
    throw new HttpError(401, 'Your session has ended. Please sign in again.');
  }

  const isPlantedDecoy = async (user, id) =>
    isDecoyId(id) && (await telemetry.honeytokens.listFor(user.id)).some((decoy) => decoy.id === id);

  // File actions are reported the way project actions are: against the project, the kind of object the
  // risk database models, with the file action and its size. Without a CrimGuard database this does nothing.
  const reportAccess = ({ req, client, user, project }, action, extra = {}) =>
    telemetry.onAccess({
      user, tokenHash: req.sessionTokenHash, client, kind: 'project', id: project.id, name: project.name, action, ...extra,
    });

  router.get('/api/projects/:id/files', async ({ req, res, params, client }) => {
    const user = sessions.requireUser(req);
    if (await isPlantedDecoy(user, params.id)) {
      sendJson(res, 200, { files: [], maxFileBytes });
      return;
    }
    const project = ownProject(user, params.id);
    const list = files.list(project.id);
    reportAccess({ req, client, user, project }, 'read', { batch: list.length });
    sendJson(res, 200, { files: list, maxFileBytes });
  });

  router.post('/api/projects/:id/files', async ({ req, res, params, client }) => {
    const user = sessions.requireUser(req);
    if (isDecoyId(params.id)) await springTrap({ req, user, id: params.id, client });
    const project = ownProject(user, params.id);
    const name = fileNameFromHeader(req.headers['x-file-name']);
    // Checked before reading the body, so a clash doesn't cost a full upload.
    if (files.nameTaken(project.id, name)) throw duplicateName(name);
    const content = await readBinary(req, res, maxFileBytes);
    await protection?.inspectUpload({ user, content, client });
    let file;
    try {
      file = files.create(project.id, { name, type: fileType(req.headers['x-file-type']), content });
    } catch (err) {
      if (err instanceof DuplicateFileNameError) throw duplicateName(name);
      throw err;
    }
    reportAccess({ req, client, user, project }, 'write', { bytes: file.size });
    sendJson(res, 201, { file });
  }, { body: 'binary' });

  router.get('/api/projects/:id/files/:fileId/download', async ({ req, res, params, client }) => {
    const user = sessions.requireUser(req);
    if (isDecoyId(params.id)) throw fileNotFound(); // a decoy has no files, matching its empty list
    const project = ownProject(user, params.id);
    const file = files.content(params.fileId, project.id);
    if (!file) throw fileNotFound();
    // A download is data leaving Red, so it goes to the risk database with its size.
    reportAccess({ req, client, user, project }, 'download', { bytes: file.content.byteLength });
    sendDownload(res, file.name, file.content);
  });

  router.patch('/api/projects/:id/files/:fileId', async ({ req, res, params, client }) => {
    const user = sessions.requireUser(req);
    if (isDecoyId(params.id)) await springTrap({ req, user, id: params.id, client });
    const project = ownProject(user, params.id);
    const existing = files.get(params.fileId, project.id);
    if (!existing) throw fileNotFound();
    const name = fileName((await readJson(req)).name);
    if (files.nameTaken(project.id, name, params.fileId)) throw duplicateName(name);
    let file;
    try {
      file = files.rename(params.fileId, project.id, name);
    } catch (err) {
      if (err instanceof DuplicateFileNameError) throw duplicateName(name);
      throw err;
    }
    if (!file) throw fileNotFound();
    // Renaming shortly before taking data out is one of the staging signals the risk catalog looks for.
    if (file.name !== existing.name) reportAccess({ req, client, user, project }, 'rename');
    sendJson(res, 200, { file });
  });

  router.put('/api/projects/:id/files/:fileId/content', async ({ req, res, params, client }) => {
    const user = sessions.requireUser(req);
    if (isDecoyId(params.id)) await springTrap({ req, user, id: params.id, client });
    const project = ownProject(user, params.id);
    if (!files.get(params.fileId, project.id)) throw fileNotFound();
    const content = await readBinary(req, res, maxFileBytes);
    await protection?.inspectUpload({ user, content, client });
    const file = files.replace(params.fileId, project.id, { type: fileType(req.headers['x-file-type']), content });
    if (!file) throw fileNotFound();
    reportAccess({ req, client, user, project }, 'write', { bytes: file.size });
    sendJson(res, 200, { file });
  }, { body: 'binary' });

  router.delete('/api/projects/:id/files/:fileId', async ({ req, res, params, client }) => {
    const user = sessions.requireUser(req);
    if (isDecoyId(params.id)) await springTrap({ req, user, id: params.id, client });
    const project = ownProject(user, params.id);
    if (!files.remove(params.fileId, project.id)) throw fileNotFound();
    reportAccess({ req, client, user, project }, 'delete');
    noContent(res);
  });

  // ---- files beyond your own projects --------------------------------------------------
  //
  // Everything below goes through files.visible*, the one place the visibility rule lives. A file
  // someone may not see answers "not found", so its existence isn't given away.

  // Files other people have shared with you, by name or through your role - and, for an account the
  // honeytrap has planted for, the decoys among them, plus the clipboard watch list.
  //
  // One endpoint carries both on purpose. A decoy served from a path of its own would be a decoy
  // that anyone can identify from the page's network traffic alone, which is the whole thing the
  // trap is trying not to be. Decoy ids come from their own reserved range (FILE_ID_BASE in
  // honeytrap/honeytrap.js), so they can never collide with a real file's.
  router.get('/api/files/shared', async ({ req, res, client }) => {
    const user = sessions.requireUser(req);
    const list = files.sharedWith(user.id);
    telemetry.onAccess({
      // Counted over the real shares only. A decoy is planted *because* a score is already high, so
      // counting it back in would let the trap feed the score that planted it.
      user, tokenHash: req.sessionTokenHash, client, kind: 'page', id: 'shared-files', name: 'Shared with me',
      action: 'read', batch: list.length,
    });
    const [lures, watch] = await Promise.all([
      protection?.honeytrap.filesFor(user) ?? [],
      protection?.honeytrap.watchList(user) ?? [],
    ]);
    sendJson(res, 200, { files: [...list, ...lures], watch });
  });

  router.get('/api/files/:fileId/download', async ({ req, res, params, client }) => {
    const user = sessions.requireUser(req);
    const file = files.visibleContent(params.fileId, user.id);
    if (!file) throw fileNotFound();
    const project = { id: file.project_id, name: file.project_name };
    reportAccess({ req, client, user, project }, 'download', { bytes: file.content.byteLength });
    // Taking a copy of someone else's file is what the activity log is for; your own files are not logged.
    if (file.owner_id !== user.id) {
      const owner = users.findById(file.owner_id);
      audit.record('file.downloaded', {
        actor: user, target: owner || null, ...client, details: { file: file.id, project: file.project_id },
      });
    }
    sendDownload(res, file.name, file.content);
  });

  const accessView = (file, access, viewer) => ({
    file: {
      id: file.id,
      name: file.name,
      confidentiality: file.confidentiality,
      project: { id: file.project_id, name: file.project_name },
      owner: { id: file.owner_id, name: file.owner_name, email: file.owner_email },
    },
    roles: access.roles,
    people: access.people,
    canManage: canManageFileAccess(viewer, file),
  });

  // Who a file is shared with. Its owner can look; admins and the CEO can look and change it.
  router.get('/api/files/:fileId/access', async ({ req, res, params }) => {
    const user = sessions.requireUser(req);
    const file = files.visible(params.fileId, user.id);
    if (!file) throw fileNotFound();
    if (file.owner_id !== user.id && !isPrivileged(user.role)) {
      throw new HttpError(403, 'Only the owner, admins and the CEO can see who has access to a file.');
    }
    sendJson(res, 200, accessView(file, files.access(file.id), user));
  });

  // Replaces a file's confidentiality and the whole list of roles and people it is shared with.
  router.put('/api/files/:fileId/access', async ({ req, res, params, client }) => {
    const actor = sessions.requireAdmin(req);
    const file = files.visible(params.fileId, actor.id);
    if (!file) throw fileNotFound();
    if (!canManageFileAccess(actor, file)) throw new HttpError(403, 'Only the CEO can change access to this file.');

    const body = await readJson(req);
    const confidentiality = Number(body.confidentiality);
    if (!isLevel(confidentiality)) {
      throw new HttpError(400, `Confidentiality must be a whole number from ${MIN_LEVEL} to ${MAX_LEVEL}.`);
    }
    if (!outranks(actor, confidentiality)) {
      throw new HttpError(403, `Your clearance lets you mark files up to ${actor.clearance} (${CONFIDENTIALITY[actor.clearance]}). Only the CEO can mark a file ${CONFIDENTIALITY[confidentiality]}.`);
    }
    const roleIds = idList(body.roles, 'Roles', MAX_ROLE_GRANTS);
    if (!roleIds.every((id) => roles.byId(id))) throw new HttpError(400, 'One of those roles no longer exists. Reload and try again.');
    // The owner can always see their own file, so they are never on the list.
    const userIds = idList(body.people, 'People', MAX_PEOPLE_GRANTS).filter((id) => id !== file.owner_id);
    if (!userIds.every((id) => users.findById(id))) throw new HttpError(400, 'One of those people no longer has an account. Reload and try again.');

    const access = files.setAccess(file.id, { confidentiality, roleIds, userIds, grantedBy: actor.id });
    audit.record('file.access_changed', {
      actor, target: { id: file.owner_id, email: file.owner_email }, ...client,
      details: {
        file: file.id,
        confidentiality: { from: file.confidentiality, to: confidentiality },
        roles: access.roles.map((role) => role.name),
        people: access.people.length,
      },
    });
    telemetry.onPrivilege({
      actor, tokenHash: req.sessionTokenHash, client, type: 'permission_change', targetRedUserId: file.owner_id,
      systemName: 'file-access', details: { file: file.id, confidentiality },
    });
    sendJson(res, 200, accessView({ ...file, confidentiality }, access, actor));
  });
}

module.exports = { registerFileRoutes };
