'use strict';

const { HttpError } = require('../http/errors');
const { readJson } = require('../http/request');
const { sendJson, noContent } = require('../http/response');
const { projectFields } = require('../validation');

function registerProjectRoutes(router, { stores, sessions }) {
  const { projects } = stores;

  router.get('/api/projects', async ({ req, res }) => {
    sendJson(res, 200, { projects: projects.list(sessions.requireUser(req).id) });
  });

  router.post('/api/projects', async ({ req, res }) => {
    const user = sessions.requireUser(req);
    const project = projects.create(user.id, projectFields(await readJson(req)));
    sendJson(res, 201, { project });
  });

  router.patch('/api/projects/:id', async ({ req, res, params }) => {
    const user = sessions.requireUser(req);
    const existing = projects.get(params.id, user.id);
    if (!existing) throw new HttpError(404, 'Project not found.');
    const project = projects.update(params.id, user.id, projectFields(await readJson(req), existing));
    sendJson(res, 200, { project });
  });

  router.delete('/api/projects/:id', async ({ req, res, params }) => {
    const user = sessions.requireUser(req);
    if (!projects.remove(params.id, user.id)) throw new HttpError(404, 'Project not found.');
    noContent(res);
  });
}

module.exports = { registerProjectRoutes };
