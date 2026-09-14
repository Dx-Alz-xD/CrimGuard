'use strict';

const { DuplicateFileNameError } = require('../db/files');
const { HttpError } = require('../http/errors');
const { readJson, readBinary } = require('../http/request');
const { sendJson, noContent } = require('../http/response');
const { isDecoyId } = require('../telemetry/honeytokens');
const { singleLine } = require('../validation');

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

function registerFileRoutes(router, { stores, sessions, telemetry, maxFileBytes, protection }) {
  const { projects, files } = stores;

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
}

module.exports = { registerFileRoutes };
