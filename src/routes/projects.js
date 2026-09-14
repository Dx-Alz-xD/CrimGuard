'use strict';

const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson, noContent } = require('../http/response');
const { projectFields } = require('../validation');
const { isDecoyId } = require('../telemetry/honeytokens');

function registerProjectRoutes(router, { stores, sessions, telemetry, protection }) {
  const { projects } = stores;

  // Taking the bait. Changing or deleting a decoy is recorded, every session this account has
  // is revoked, and the request is refused as a signed-out one - which is what sends the
  // browser back to the sign-in page.
  //
  // The id being in the decoy range is not enough on its own: trip() returns null unless there
  // is a live decoy with that id planted for this very account. Otherwise anyone could sign
  // themselves out by guessing a number, and the request falls through to the ordinary
  // "no such project" instead.
  async function springTrap({ req, user, id, interaction, client }) {
    const report = await telemetry.honeytokens.trip({
      user, decoyId: id, interaction, client, tokenHash: req.sessionTokenHash,
    });
    if (!report) return;

    stores.sessions.removeAll(user.id);
    stores.audit.record('security.honeytoken_tripped', {
      actor: user, target: user, ...client, details: { interaction, decoy: report.decoy, score: report.score },
    });
    // The identity throttle turns it into a freeze: signing back in waits for an admin.
    await protection?.onHoneytokenTrip(report);
    throw new HttpError(401, 'Your session has ended. Please sign in again.');
  }

  // Listing is one access of the project list, carrying how many it returned, rather than one
  // access per project: opening the dashboard is not the same as opening every project on it.
  router.get('/api/projects', async ({ req, res, client }) => {
    const user = sessions.requireUser(req);
    const list = projects.list(user.id);
    telemetry.onAccess({
      user, tokenHash: req.sessionTokenHash, client, kind: 'page', id: 'projects', name: 'Projects',
      action: 'read', batch: list.length,
    });
    // Any decoy planted for this account sits in the list like anything else. It is theirs
    // alone, and it is indistinguishable from a real project until someone tries to change it.
    const decoys = await telemetry.honeytokens.listFor(user.id);
    sendJson(res, 200, { projects: [...decoys, ...list] });
  });

  // Everything the account owns, as a file. This is the one way data leaves Red, and so the
  // source behind daily_download_volume_mb and the export half of
  // file_rename_before_export_count.
  router.get('/api/projects/export', async ({ req, res, client }) => {
    const user = sessions.requireUser(req);
    const list = projects.list(user.id);
    const body = JSON.stringify({ exportedAt: new Date().toISOString(), account: user.email, projects: list }, null, 2);
    const bytes = Buffer.byteLength(body);

    telemetry.onExport({ user, tokenHash: req.sessionTokenHash, client, bytes, items: list.length });
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': 'attachment; filename="red-projects.json"',
      'Cache-Control': 'no-store',
    });
    res.end(body);
  });

  router.post('/api/projects', async ({ req, res, client }) => {
    const user = sessions.requireUser(req);
    const fields = projectFields(await readJson(req));
    await protection?.inspectText({ user, text: `${fields.name}\n${fields.description}`, channel: 'project_text', client });
    const project = projects.create(user.id, fields);
    telemetry.onAccess({
      user, tokenHash: req.sessionTokenHash, client, kind: 'project', id: project.id, name: project.name, action: 'write',
    });
    telemetry.onText({ user, tokenHash: req.sessionTokenHash, client, text: `${fields.name}\n${fields.description}` });
    sendJson(res, 201, { project });
  });

  router.patch('/api/projects/:id', async ({ req, res, params, client }) => {
    const user = sessions.requireUser(req);
    if (isDecoyId(params.id)) await springTrap({ req, user, id: params.id, interaction: 'modified', client });
    const existing = projects.get(params.id, user.id);
    if (!existing) throw new HttpError(404, 'Project not found.');
    const fields = projectFields(await readJson(req), existing);
    await protection?.inspectText({ user, text: `${fields.name}\n${fields.description}`, channel: 'project_text', client });
    const project = projects.update(params.id, user.id, fields);

    // A rename is its own action: renaming something shortly before exporting it is one of the
    // staging signals the catalog looks for.
    const renamed = fields.name !== existing.name;
    telemetry.onAccess({
      user, tokenHash: req.sessionTokenHash, client, kind: 'project', id: project.id, name: project.name,
      action: renamed ? 'rename' : 'write', previousName: renamed ? existing.name : null,
    });
    if (fields.description !== existing.description || renamed) {
      telemetry.onText({ user, tokenHash: req.sessionTokenHash, client, text: `${fields.name}\n${fields.description}` });
    }
    sendJson(res, 200, { project });
  });

  router.delete('/api/projects/:id', async ({ req, res, params, client }) => {
    const user = sessions.requireUser(req);
    if (isDecoyId(params.id)) await springTrap({ req, user, id: params.id, interaction: 'deleted', client });
    const existing = projects.get(params.id, user.id);
    if (!existing || !projects.remove(params.id, user.id)) throw new HttpError(404, 'Project not found.');
    telemetry.onAccess({
      user, tokenHash: req.sessionTokenHash, client, kind: 'project', id: params.id, name: existing.name, action: 'delete',
    });
    noContent(res);
  });
}

module.exports = { registerProjectRoutes };
