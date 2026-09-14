'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { HttpError } = require('./errors');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function sendJson(res, status, data, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(data));
}

function noContent(res) {
  res.writeHead(204, { 'Cache-Control': 'no-store' });
  res.end();
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, 'Cache-Control': 'no-store' });
  res.end();
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': MIME_TYPES['.html'], 'Cache-Control': 'no-store' });
  res.end(html);
}

async function serveStatic(res, staticDir, relative) {
  const file = path.resolve(staticDir, relative);
  const type = MIME_TYPES[path.extname(file)];
  if (!file.startsWith(staticDir + path.sep) || !type) throw new HttpError(404, 'Not found.');

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

module.exports = { MIME_TYPES, sendJson, noContent, redirect, sendHtml, serveStatic };
