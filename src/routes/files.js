'use strict';

const { DuplicateFileNameError } = require('../db/files');
const { HttpError } = require('../http/errors');
const { readJson, readBinary } = require('../http/request');
const { sendJson, noContent } = require('../http/response');
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

function registerFileRoutes(router, { stores, sessions, maxFileBytes }) {
  const { projects, files } = stores;

  // Files are reached only through a project the signed-in person owns; for anyone else it doesn't exist.
  function ownProject(req, projectId) {
    const project = projects.get(projectId, sessions.requireUser(req).id);
    if (!project) throw new HttpError(404, 'Project not found.');
    return project;
  }

  router.get('/api/projects/:id/files', async ({ req, res, params }) => {
    const project = ownProject(req, params.id);
    sendJson(res, 200, { files: files.list(project.id), maxFileBytes });
  });

  router.post('/api/projects/:id/files', async ({ req, res, params }) => {
    const project = ownProject(req, params.id);
    const name = fileNameFromHeader(req.headers['x-file-name']);
    // Checked before reading the body, so a clash doesn't cost a full upload.
    if (files.nameTaken(project.id, name)) throw duplicateName(name);
    const content = await readBinary(req, res, maxFileBytes);
    try {
      sendJson(res, 201, { file: files.create(project.id, { name, type: fileType(req.headers['x-file-type']), content }) });
    } catch (err) {
      if (err instanceof DuplicateFileNameError) throw duplicateName(name);
      throw err;
    }
  }, { body: 'binary' });

  router.get('/api/projects/:id/files/:fileId/download', async ({ req, res, params }) => {
    const project = ownProject(req, params.id);
    const file = files.content(params.fileId, project.id);
    if (!file) throw fileNotFound();
    sendDownload(res, file.name, file.content);
  });

  router.patch('/api/projects/:id/files/:fileId', async ({ req, res, params }) => {
    const project = ownProject(req, params.id);
    if (!files.get(params.fileId, project.id)) throw fileNotFound();
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
    sendJson(res, 200, { file });
  });

  router.put('/api/projects/:id/files/:fileId/content', async ({ req, res, params }) => {
    const project = ownProject(req, params.id);
    if (!files.get(params.fileId, project.id)) throw fileNotFound();
    const content = await readBinary(req, res, maxFileBytes);
    const file = files.replace(params.fileId, project.id, { type: fileType(req.headers['x-file-type']), content });
    if (!file) throw fileNotFound();
    sendJson(res, 200, { file });
  }, { body: 'binary' });

  router.delete('/api/projects/:id/files/:fileId', async ({ req, res, params }) => {
    const project = ownProject(req, params.id);
    if (!files.remove(params.fileId, project.id)) throw fileNotFound();
    noContent(res);
  });
}

module.exports = { registerFileRoutes };
