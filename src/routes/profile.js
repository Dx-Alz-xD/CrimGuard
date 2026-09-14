'use strict';

// A person's own details: name, job title, team, and a short bio.

const { readJson } = require('../http/request');
const { sendJson } = require('../http/response');
const { profileFields } = require('../validation');

const profileOut = (row) => ({
  id: row.id,
  name: row.name,
  email: row.email,
  role: row.role,
  jobTitle: row.job_title,
  organization: row.organization,
  bio: row.bio,
  createdAt: row.created_at,
  lastLoginAt: row.last_login_at,
  passwordChangedAt: row.password_changed_at,
});

function registerProfileRoutes(router, { stores, sessions }) {
  const { users, audit } = stores;

  router.get('/api/me/profile', async ({ req, res }) => {
    const user = sessions.requireUser(req);
    sendJson(res, 200, { profile: profileOut(users.profile(user.id)) });
  });

  router.patch('/api/me/profile', async ({ req, res, client }) => {
    const user = sessions.requireUser(req);
    const current = users.profile(user.id);
    const fields = profileFields(await readJson(req), current);
    users.updateProfile(user.id, fields);

    const changed = [['name', 'name'], ['jobTitle', 'job_title'], ['organization', 'organization'], ['bio', 'bio']]
      .filter(([key, column]) => fields[key] !== current[column])
      .map(([key]) => key);
    if (changed.length) audit.record('profile.updated', { actor: user, target: user, ...client, details: { fields: changed } });

    sendJson(res, 200, { profile: profileOut(users.profile(user.id)) });
  });
}

module.exports = { registerProfileRoutes };
