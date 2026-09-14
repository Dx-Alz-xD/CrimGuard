'use strict';

// Red static demo. Stands in for the Node server so the real pages run straight from the file system
// or any static host, following the same rules as the routes in src/routes/. Everything lives in this browser's
// localStorage, and passwords here are plain text: it is a demo, never a place for real accounts.
(() => {
  const STORAGE_KEY = 'red-demo:v2';
  const ROLES = ['user', 'admin'];
  const STATUSES = ['planning', 'active', 'done'];
  const PAGE_FILES = {
    '/': 'index.html',
    '/login': 'login.html',
    '/admin/login': 'admin-login.html',
    '/signup': 'signup.html',
    '/dashboard': 'dashboard.html',
    '/admin': 'admin.html',
  };

  window.RED_ROUTE = (target) => {
    const [pathname, hash] = target.split('#');
    return (PAGE_FILES[pathname] || pathname) + (hash ? `#${hash}` : '');
  };

  // ---- data ------------------------------------------------------------------------

  const sqlTime = (date) => date.toISOString().slice(0, 19).replace('T', ' ');
  const now = () => sqlTime(new Date());
  const daysAgo = (days) => sqlTime(new Date(Date.now() - days * 86400000));

  function seed() {
    const user = (id, name, email, password, role, age) =>
      ({ id, name, email, password, role, created_at: daysAgo(age), last_login_at: daysAgo(Math.min(age, 2)), must_change_password: false, job_title: '', organization: '', bio: '' });
    const project = (id, ownerId, name, status, description, age) =>
      ({ id, owner_id: ownerId, name, status, description, created_at: daysAgo(age + 12), updated_at: daysAgo(age) });
    return {
      session: null,
      nextUserId: 6,
      nextProjectId: 10,
      nextEventId: 1,
      audit: [],
      users: [
        user(1, 'Maya Okafor', 'admin@red.demo', 'admin-demo', 'admin', 120),
        user(2, 'Sam Carter', 'user@red.demo', 'user-demo', 'user', 64),
        user(3, 'Amara Osei', 'amara@red.demo', 'amara-demo', 'admin', 40),
        user(4, 'Jonas Weber', 'jonas@red.demo', 'jonas-demo', 'user', 21),
        user(5, 'Lena Fischer', 'lena@red.demo', 'lena-demo', 'user', 6),
      ],
      projects: [
        project(1, 2, 'Customer onboarding flow', 'active', 'Map the first week for new customers and remove the steps before their first project.', 1),
        project(2, 2, 'Quarterly pricing review', 'planning', 'Compare plan usage with price points before the October review.', 4),
        project(3, 2, 'Help center migration', 'done', 'Move 140 articles to the new help center and redirect the old links.', 18),
        project(4, 1, 'Q3 access review', 'active', 'Confirm that everyone with the Admin role still needs it.', 2),
        project(5, 1, 'Single sign-on rollout', 'planning', 'Choose an identity provider and pilot it with two teams.', 9),
        project(6, 3, 'Security awareness training', 'active', '', 3),
        project(7, 4, 'Warehouse scanner app', 'active', 'Replace paper pick lists in the Leipzig warehouse.', 5),
        project(8, 4, 'Supplier portal', 'planning', '', 12),
        project(9, 5, 'Office move checklist', 'done', '', 30),
      ],
    };
  }

  let db;
  try {
    db = JSON.parse(localStorage.getItem(STORAGE_KEY)) || seed();
  } catch {
    db = seed();
  }
  const save = () => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(db)); } catch { /* storage blocked: the demo still works for this page view */ }
  };
  save();

  // ---- the same rules as the server ------------------------------------------------------

  const fail = (status, error, code) => { throw { status, error, code }; };
  const publicUser = ({ id, name, email, role }) => ({ id, name, email, role });
  const homeFor = (user) => (user.role === 'admin' ? '/admin' : '/dashboard');
  const currentUser = () => db.users.find((user) => user.id === db.session) || null;

  const requireUser = ({ allowPasswordChange = false } = {}) => {
    const user = currentUser() || fail(401, 'Please sign in.');
    if (user.must_change_password && !allowPasswordChange) fail(403, 'Choose a new password to continue.', 'password_change_required');
    return user;
  };
  const record = (action, actor, target, details = {}) => {
    db.audit.unshift({ id: db.nextEventId++, occurred_at: now(), action, actor_email: actor ? actor.email : null, target_email: target ? target.email : null, ip: 'demo', details });
    db.audit = db.audit.slice(0, 200);
  };
  const requireAdmin = () => {
    const user = requireUser();
    if (user.role !== 'admin') fail(403, 'Admin access required.');
    return user;
  };

  const singleLine = (value) => (typeof value === 'string' ? value.replace(/\s+/g, ' ').trim() : '');
  const normalizeEmail = (value) => {
    const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
    return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : '';
  };
  // A shorter version of src/security/password-policy.js.
  const validPassword = (value) => {
    const password = typeof value === 'string' ? value : '';
    if (password.length < 12 || password.length > 256) fail(400, 'Password must be 12 to 256 characters.');
    if (new Set(password.toLowerCase()).size <= 2 || /^(password|qwerty|123456)/i.test(password)) {
      fail(400, 'That password is too easy to guess. Try a longer phrase of unrelated words.');
    }
    return password;
  };

  function createAccount(body, role, mustChange = false) {
    const name = singleLine(body.name);
    const email = normalizeEmail(body.email);
    if (!name || name.length > 80) fail(400, 'Enter a name (up to 80 characters).');
    if (!email) fail(400, 'Enter a valid email address.');
    const password = validPassword(body.password);
    if (db.users.some((user) => user.email === email)) fail(409, 'An account with that email already exists.');
    const user = { id: db.nextUserId++, name, email, password, role, created_at: now(), last_login_at: null, must_change_password: mustChange, job_title: '', organization: '', bio: '' };
    db.users.push(user);
    return user;
  }

  function projectFields(body, current = { name: '', description: '', status: 'planning' }) {
    const has = (key) => Object.prototype.hasOwnProperty.call(body, key);
    const name = has('name') ? singleLine(body.name) : current.name;
    const description = has('description') ? (typeof body.description === 'string' ? body.description.trim() : '') : current.description;
    const status = has('status') ? body.status : current.status;
    if (!name) fail(400, 'Project name is required.');
    if (name.length > 120) fail(400, 'Project name must be 120 characters or fewer.');
    if (description.length > 2000) fail(400, 'Description must be 2000 characters or fewer.');
    if (!STATUSES.includes(status)) fail(400, `Status must be one of: ${STATUSES.join(', ')}.`);
    return { name, description, status };
  }

  const projectOut = ({ id, name, description, status, created_at, updated_at }) => ({ id, name, description, status, created_at, updated_at });
  const findOwnProject = (id, user) => db.projects.find((project) => project.id === id && project.owner_id === user.id);
  const profileOut = (user) => ({ id: user.id, name: user.name, email: user.email, role: user.role, jobTitle: user.job_title, organization: user.organization, bio: user.bio, createdAt: user.created_at, lastLoginAt: user.last_login_at });
  const findUser = (id) => db.users.find((user) => user.id === id) || fail(404, 'User not found.');

  function handle(method, pathname, body) {
    const id = Number((pathname.match(/\/(\d{1,15})(?:\/|$)/) || [])[1]);
    const routeKey = `${method} ${pathname.replace(/\/\d{1,15}(?=\/|$)/, '/:id')}`;

    switch (routeKey) {
      case 'POST /api/signup': {
        const user = createAccount(body, 'user');
        db.session = user.id;
        record('account.signup', user, user);
        return [201, { user: publicUser(user), redirect: homeFor(user) }];
      }
      case 'POST /api/login': {
        const user = db.users.find((u) => u.email === normalizeEmail(body.email));
        if (!user || user.password !== body.password) {
          record('login.failed', null, user || null, { portal: body.portal === 'admin' ? 'admin' : 'user', blocked: false });
          fail(401, 'Incorrect email or password.');
        }
        if (body.portal === 'admin' && user.role !== 'admin') fail(403, "This account doesn't have admin access. Use the user login.");
        if (body.portal !== 'admin' && user.role === 'admin') fail(403, 'This is an admin account. Use the admin login.');
        db.session = user.id;
        user.last_login_at = now();
        record('login.succeeded', user, user, { portal: body.portal === 'admin' ? 'admin' : 'user' });
        return [200, { user: publicUser(user), redirect: homeFor(user), mustChangePassword: user.must_change_password }];
      }
      case 'POST /api/logout': {
        const user = currentUser();
        if (user) record('logout', user, user);
        db.session = null;
        return [200, { redirect: '/' }];
      }
      case 'GET /api/me': {
        const user = requireUser({ allowPasswordChange: true });
        return [200, { user: { ...publicUser(user), mustChangePassword: user.must_change_password } }];
      }
      case 'PATCH /api/me/password': {
        const user = requireUser({ allowPasswordChange: true });
        const newPassword = validPassword(body.newPassword);
        if (body.currentPassword !== user.password) {
          record('password.change_failed', user, user);
          fail(400, 'Your current password is incorrect.');
        }
        if (newPassword === body.currentPassword) fail(400, 'Choose a new password that is different from your current one.');
        user.password = newPassword;
        user.must_change_password = false;
        record('password.changed', user, user);
        return [200, { ok: true }];
      }
      case 'GET /api/me/profile': {
        const user = requireUser();
        return [200, { profile: profileOut(user) }];
      }
      case 'PATCH /api/me/profile': {
        const user = requireUser();
        const has = (key) => Object.prototype.hasOwnProperty.call(body, key);
        const name = has('name') ? singleLine(body.name) : user.name;
        const jobTitle = has('jobTitle') ? singleLine(body.jobTitle) : user.job_title;
        const organization = has('organization') ? singleLine(body.organization) : user.organization;
        const bio = has('bio') ? (typeof body.bio === 'string' ? body.bio.trim() : '') : user.bio;
        if (!name || name.length > 80) fail(400, 'Enter a name (up to 80 characters).');
        if (jobTitle.length > 80) fail(400, 'Job title must be 80 characters or fewer.');
        if (organization.length > 80) fail(400, 'Team or organization must be 80 characters or fewer.');
        if (bio.length > 500) fail(400, 'About you must be 500 characters or fewer.');
        Object.assign(user, { name, job_title: jobTitle, organization, bio });
        record('profile.updated', user, user, {});
        return [200, { profile: profileOut(user) }];
      }

      case 'GET /api/projects': {
        const user = requireUser();
        const own = db.projects
          .filter((project) => project.owner_id === user.id)
          .sort((a, b) => b.updated_at.localeCompare(a.updated_at) || b.id - a.id);
        return [200, { projects: own.map(projectOut) }];
      }
      case 'POST /api/projects': {
        const user = requireUser();
        const project = { id: db.nextProjectId++, owner_id: user.id, ...projectFields(body), created_at: now(), updated_at: now() };
        db.projects.push(project);
        return [201, { project: projectOut(project) }];
      }
      case 'PATCH /api/projects/:id': {
        const user = requireUser();
        const project = findOwnProject(id, user) || fail(404, 'Project not found.');
        Object.assign(project, projectFields(body, project), { updated_at: now() });
        return [200, { project: projectOut(project) }];
      }
      case 'DELETE /api/projects/:id': {
        const user = requireUser();
        const project = findOwnProject(id, user) || fail(404, 'Project not found.');
        db.projects = db.projects.filter((p) => p !== project);
        return [204, null];
      }

      case 'GET /api/admin/users': {
        requireAdmin();
        const users = db.users
          .slice()
          .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id - b.id)
          .map((user) => ({
            ...publicUser(user),
            created_at: user.created_at,
            last_login_at: user.last_login_at,
            project_count: db.projects.filter((project) => project.owner_id === user.id).length,
          }));
        return [200, { users }];
      }
      case 'POST /api/admin/users': {
        const admin = requireAdmin();
        if (!ROLES.includes(body.role)) fail(400, 'Choose a role: user or admin.');
        const user = createAccount(body, body.role, true);
        record('admin.user_created', admin, user, { role: user.role });
        return [201, { user: publicUser(user) }];
      }
      case 'PATCH /api/admin/users/:id/role': {
        const admin = requireAdmin();
        if (!ROLES.includes(body.role)) fail(400, 'Choose a role: user or admin.');
        if (id === admin.id) fail(400, "You can't change your own role. Ask another admin.");
        const user = findUser(id);
        if (user.role !== body.role) record('admin.role_changed', admin, user, { from: user.role, to: body.role });
        user.role = body.role;
        return [200, { user: publicUser(user) }];
      }
      case 'PATCH /api/admin/users/:id/password': {
        const admin = requireAdmin();
        const password = validPassword(body.password);
        const user = findUser(id);
        user.password = password;
        user.must_change_password = user.id !== admin.id;
        record('admin.password_reset', admin, user);
        return [200, { ok: true }];
      }
      case 'DELETE /api/admin/users/:id': {
        const admin = requireAdmin();
        if (id === admin.id) fail(400, "You can't delete your own account. Ask another admin.");
        const user = findUser(id);
        db.users = db.users.filter((u) => u.id !== id);
        db.projects = db.projects.filter((project) => project.owner_id !== id);
        record('admin.user_deleted', admin, user, { role: user.role });
        return [204, null];
      }
      case 'GET /api/admin/audit': {
        requireAdmin();
        return [200, { events: db.audit, nextBefore: null }];
      }

      default:
        return fail(404, 'Not found.');
    }
  }

  const realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    if (!url.startsWith('/api/')) return realFetch(input, init);

    let body = {};
    try { body = init.body ? JSON.parse(init.body) : {}; } catch { body = {}; }
    await new Promise((resolve) => setTimeout(resolve, 90)); // enough delay for loading states to appear, as they would live

    const json = (status, data) =>
      new Response(data == null ? null : JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
    try {
      const [status, data] = handle((init.method || 'GET').toUpperCase(), url.split('?')[0], body);
      save();
      return json(status, data);
    } catch (err) {
      if (!err || typeof err.status !== 'number') throw err;
      return json(err.status, err.code ? { error: err.error, code: err.code } : { error: err.error });
    }
  };

  // ---- page guards and demo hints ------------------------------------------------------

  const page = document.body.dataset.page;
  const portal = document.body.dataset.portal;
  const pagePath = { landing: '/', login: portal === 'admin' ? '/admin/login' : '/login', signup: '/signup', dashboard: '/dashboard', admin: '/admin' }[page];

  // The server redirects these page requests; the demo does it here, with the same rules.
  function pageRedirect(pathname, user) {
    switch (pathname) {
      case '/':
      case '/login':
      case '/signup':
        return user ? homeFor(user) : null;
      case '/admin/login':
        return user && user.role === 'admin' ? '/admin' : null;
      case '/dashboard':
        if (!user) return '/login';
        return user.role === 'admin' ? '/admin' : null;
      case '/admin':
        if (!user) return '/admin/login';
        return user.role === 'admin' ? null : '/dashboard';
      default:
        return null;
    }
  }

  const redirect = pathPath => pageRedirect(pathPath, currentUser());
  const target = pagePath && redirect(pagePath);
  if (target) {
    location.replace(window.RED_ROUTE(target));
    return;
  }

  const el = (tag, className, ...children) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.append(...children);
    return node;
  };

  if (page === 'login') {
    const [email, password] = portal === 'admin' ? ['admin@red.demo', 'admin-demo'] : ['user@red.demo', 'user-demo'];
    const fill = el('button', 'btn btn-secondary btn-sm', 'Fill in');
    fill.type = 'button';
    fill.addEventListener('click', () => {
      document.getElementById('email').value = email;
      document.getElementById('password').value = password;
    });
    const note = el('div', 'demo-note demo-account',
      el('span', '', 'Demo account: ', el('strong', '', email), ' / ', el('strong', '', password)),
      fill);
    document.getElementById('auth-form').before(note);
  }

  const reset = el('button', 'btn btn-quiet btn-sm', 'Reset demo');
  reset.type = 'button';
  reset.addEventListener('click', () => {
    if (!confirm('Reset the demo? This restores the sample people and projects and signs you out.')) return;
    try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
    location.assign(window.RED_ROUTE('/'));
  });
  document.body.append(el('div', 'demo-flag', el('span', '', 'Demo: changes stay in this browser'), reset));
})();
