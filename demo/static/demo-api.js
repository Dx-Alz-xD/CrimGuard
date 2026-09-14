'use strict';

// Red static demo. Stands in for the Node server so the real pages run straight from the file system
// or any static host, following the same rules as src/app.js. Everything lives in this browser's
// localStorage, and passwords here are plain text: it is a demo, never a place for real accounts.
(() => {
  const STORAGE_KEY = 'red-demo:v1';
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

  // Browser storage holds about 5 MB, and file contents are kept as base64, so the demo's limit is smaller than the server's.
  const DEMO_MAX_FILE_BYTES = 1024 * 1024;
  const bytesToBase64 = (bytes) => {
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(binary);
  };
  const base64ToBytes = (base64) => Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  const textBytes = (text) => new TextEncoder().encode(text);

  function seed() {
    const user = (id, name, email, password, role, age) => ({ id, name, email, password, role, created_at: daysAgo(age) });
    const project = (id, ownerId, name, status, description, age) =>
      ({ id, owner_id: ownerId, name, status, description, created_at: daysAgo(age + 12), updated_at: daysAgo(age) });
    const file = (id, projectId, name, type, text, age) =>
      ({ id, project_id: projectId, name, type, size: textBytes(text).length, content: bytesToBase64(textBytes(text)), created_at: daysAgo(age + 1), updated_at: daysAgo(age) });
    return {
      session: null,
      nextUserId: 6,
      nextProjectId: 10,
      nextFileId: 4,
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
      files: [
        file(1, 1, 'onboarding-checklist.md', 'text/markdown', '# First week checklist\n\n- Invite the team\n- Create the first project\n- Upload the kickoff notes\n', 1),
        file(2, 1, 'kickoff-notes.txt', 'text/plain', 'Kickoff, 2 September\nGoal: new customers reach their first project on day one.\n', 3),
        file(3, 2, 'plan-usage.csv', 'text/csv', 'plan,accounts,avg_projects\nStarter,412,3.1\nTeam,138,9.4\nBusiness,27,21.7\n', 4),
      ],
    };
  }

  let db;
  try {
    db = JSON.parse(localStorage.getItem(STORAGE_KEY)) || seed();
  } catch {
    db = seed();
  }
  // Demo data saved before files existed has no file list yet.
  db.files = db.files || [];
  db.nextFileId = db.nextFileId || 1;

  // Returns false only when storage is full. Blocked storage is ignored: the demo still works for this page view.
  const save = () => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(db));
    } catch (err) {
      if (err && err.name === 'QuotaExceededError') return false;
    }
    return true;
  };
  save();

  // ---- the same rules as the server ------------------------------------------------------

  const fail = (status, error) => { throw { status, error }; };
  const publicUser = ({ id, name, email, role }) => ({ id, name, email, role });
  const homeFor = (user) => (user.role === 'admin' ? '/admin' : '/dashboard');
  const currentUser = () => db.users.find((user) => user.id === db.session) || null;

  const requireUser = () => currentUser() || fail(401, 'Please sign in.');
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
  const validPassword = (value) => {
    const password = typeof value === 'string' ? value : '';
    if (password.length < 8 || password.length > 200) fail(400, 'Password must be 8 to 200 characters.');
    return password;
  };

  function createAccount(body, role) {
    const name = singleLine(body.name);
    const email = normalizeEmail(body.email);
    if (!name || name.length > 80) fail(400, 'Enter a name (up to 80 characters).');
    if (!email) fail(400, 'Enter a valid email address.');
    const password = validPassword(body.password);
    if (db.users.some((user) => user.email === email)) fail(409, 'An account with that email already exists.');
    const user = { id: db.nextUserId++, name, email, password, role, created_at: now() };
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

  const projectOut = ({ id, name, description, status, created_at, updated_at }) =>
    ({ id, name, description, status, created_at, updated_at, file_count: db.files.filter((f) => f.project_id === id).length });
  const fileOut = ({ id, name, type, size, created_at, updated_at }) => ({ id, name, type, size, created_at, updated_at });
  const findOwnProject = (id, user) => db.projects.find((project) => project.id === id && project.owner_id === user.id);
  const findUser = (id) => db.users.find((user) => user.id === id) || fail(404, 'User not found.');

  // ---- files, with the same rules as the server ---------------------------------------------

  function cleanFileName(value) {
    const name = (typeof value === 'string' ? value : '')
      .split(/[\\/]/)
      .pop()
      .replace(/[\u0000-\u001f\u007f]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
    if (!name || name === '.' || name === '..') fail(400, 'Give the file a name.');
    if (name.length > 255) fail(400, 'File names can be up to 255 characters.');
    return name;
  }

  function fileNameFromHeader(value) {
    let decoded;
    try { decoded = decodeURIComponent(String(value ?? '')); } catch { fail(400, 'The file name could not be read.'); }
    return cleanFileName(decoded);
  }

  const fileType = (value) => {
    const type = String(value ?? '').trim().toLowerCase();
    return type.length <= 100 && /^[a-z0-9][\w!#$&^.+-]*\/[a-z0-9][\w!#$&^.+-]*$/.test(type) ? type : 'application/octet-stream';
  };
  const requireOwnProject = (projectId) => findOwnProject(projectId, requireUser()) || fail(404, 'Project not found.');
  const findFile = (project, fileId) => db.files.find((f) => f.id === fileId && f.project_id === project.id) || fail(404, 'File not found.');
  const nameTaken = (project, name, exceptId) =>
    db.files.some((f) => f.project_id === project.id && f.id !== exceptId && f.name.toLowerCase() === name.toLowerCase());
  const duplicateName = (name) => fail(409, `A file named "${name}" is already in this project. Rename one of them, or replace the existing file.`);
  const checkSize = (bytes) => {
    if (bytes.length > DEMO_MAX_FILE_BYTES) fail(413, 'Files can be up to 1 MB in the demo, which keeps them in this browser.');
  };

  function handle(method, pathname, body, request) {
    // Numeric path segments become ":id" in the route key; the first is `id`, the second (a file) is `subId`.
    const [id, subId] = [...pathname.matchAll(/\/(\d{1,15})(?=\/|$)/g)].map((match) => Number(match[1]));
    const routeKey = `${method} ${pathname.replace(/\/\d{1,15}(?=\/|$)/g, '/:id')}`;

    switch (routeKey) {
      case 'POST /api/signup': {
        const user = createAccount(body, 'user');
        db.session = user.id;
        return [201, { user: publicUser(user), redirect: homeFor(user) }];
      }
      case 'POST /api/login': {
        const user = db.users.find((u) => u.email === normalizeEmail(body.email));
        if (!user || user.password !== body.password) fail(401, 'Incorrect email or password.');
        if (body.portal === 'admin' && user.role !== 'admin') fail(403, "This account doesn't have admin access. Use the user login.");
        if (body.portal !== 'admin' && user.role === 'admin') fail(403, 'This is an admin account. Use the admin login.');
        db.session = user.id;
        return [200, { user: publicUser(user), redirect: homeFor(user) }];
      }
      case 'POST /api/logout':
        db.session = null;
        return [200, { redirect: '/' }];
      case 'GET /api/me':
        return [200, { user: publicUser(requireUser()) }];
      case 'PATCH /api/me/password': {
        const user = requireUser();
        const newPassword = validPassword(body.newPassword);
        if (body.currentPassword !== user.password) fail(400, 'Your current password is incorrect.');
        if (newPassword === body.currentPassword) fail(400, 'Choose a new password that is different from your current one.');
        user.password = newPassword;
        return [200, { ok: true }];
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
        db.files = db.files.filter((f) => f.project_id !== project.id);
        return [204, null];
      }

      case 'GET /api/projects/:id/files': {
        const project = requireOwnProject(id);
        const files = db.files
          .filter((f) => f.project_id === project.id)
          .sort((a, b) => b.updated_at.localeCompare(a.updated_at) || b.id - a.id);
        return [200, { files: files.map(fileOut), maxFileBytes: DEMO_MAX_FILE_BYTES }];
      }
      case 'POST /api/projects/:id/files': {
        const project = requireOwnProject(id);
        const name = fileNameFromHeader(request.headers['x-file-name']);
        if (nameTaken(project, name)) duplicateName(name);
        const bytes = request.bytes || new Uint8Array();
        checkSize(bytes);
        const saved = { id: db.nextFileId++, project_id: project.id, name, type: fileType(request.headers['x-file-type']), size: bytes.length, content: bytesToBase64(bytes), created_at: now(), updated_at: now() };
        db.files.push(saved);
        project.updated_at = now();
        return [201, { file: fileOut(saved) }];
      }
      case 'GET /api/projects/:id/files/:id/download': {
        const file = findFile(requireOwnProject(id), subId);
        return [200, null, base64ToBytes(file.content)];
      }
      case 'PATCH /api/projects/:id/files/:id': {
        const project = requireOwnProject(id);
        const file = findFile(project, subId);
        const name = cleanFileName(body.name);
        if (nameTaken(project, name, file.id)) duplicateName(name);
        Object.assign(file, { name, updated_at: now() });
        project.updated_at = now();
        return [200, { file: fileOut(file) }];
      }
      case 'PUT /api/projects/:id/files/:id/content': {
        const project = requireOwnProject(id);
        const file = findFile(project, subId);
        const bytes = request.bytes || new Uint8Array();
        checkSize(bytes);
        Object.assign(file, { type: fileType(request.headers['x-file-type']), size: bytes.length, content: bytesToBase64(bytes), updated_at: now() });
        project.updated_at = now();
        return [200, { file: fileOut(file) }];
      }
      case 'DELETE /api/projects/:id/files/:id': {
        const project = requireOwnProject(id);
        const file = findFile(project, subId);
        db.files = db.files.filter((f) => f !== file);
        project.updated_at = now();
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
            project_count: db.projects.filter((project) => project.owner_id === user.id).length,
          }));
        return [200, { users }];
      }
      case 'POST /api/admin/users': {
        requireAdmin();
        if (!ROLES.includes(body.role)) fail(400, 'Choose a role: user or admin.');
        return [201, { user: publicUser(createAccount(body, body.role)) }];
      }
      case 'PATCH /api/admin/users/:id/role': {
        const admin = requireAdmin();
        if (!ROLES.includes(body.role)) fail(400, 'Choose a role: user or admin.');
        if (id === admin.id) fail(400, "You can't change your own role. Ask another admin.");
        const user = findUser(id);
        user.role = body.role;
        return [200, { user: publicUser(user) }];
      }
      case 'PATCH /api/admin/users/:id/password': {
        requireAdmin();
        const password = validPassword(body.password);
        findUser(id).password = password;
        return [200, { ok: true }];
      }
      case 'DELETE /api/admin/users/:id': {
        const admin = requireAdmin();
        if (id === admin.id) fail(400, "You can't delete your own account. Ask another admin.");
        findUser(id);
        db.users = db.users.filter((user) => user.id !== id);
        const removedProjects = new Set(db.projects.filter((project) => project.owner_id === id).map((project) => project.id));
        db.files = db.files.filter((f) => !removedProjects.has(f.project_id));
        db.projects = db.projects.filter((project) => project.owner_id !== id);
        return [204, null];
      }

      default:
        return fail(404, 'Not found.');
    }
  }

  const realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    if (!url.startsWith('/api/')) return realFetch(input, init);

    const method = (init.method || 'GET').toUpperCase();
    const headers = {};
    for (const [key, value] of Object.entries(init.headers instanceof Headers ? Object.fromEntries(init.headers) : init.headers || {})) {
      headers[key.toLowerCase()] = String(value);
    }

    // JSON writes arrive as strings; uploads arrive as a File or Blob.
    let body = {};
    let bytes = null;
    if (typeof init.body === 'string') {
      try { body = JSON.parse(init.body); } catch { body = {}; }
    } else if (init.body instanceof Blob) {
      bytes = new Uint8Array(await init.body.arrayBuffer());
    } else if (init.body instanceof ArrayBuffer || ArrayBuffer.isView(init.body)) {
      bytes = new Uint8Array(init.body.buffer || init.body, init.body.byteOffset || 0, init.body.byteLength);
    }
    await new Promise((resolve) => setTimeout(resolve, 90)); // enough delay for loading states to appear, as they would live

    const json = (status, data) =>
      new Response(data == null ? null : JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
    const snapshot = method === 'GET' ? null : JSON.stringify(db);
    try {
      const [status, data, raw] = handle(method, url.split('?')[0], body, { headers, bytes });
      if (snapshot && !save()) {
        db = JSON.parse(snapshot); // storage is full: undo this change rather than keep data that won't survive a reload
        return json(507, { error: "This browser's storage for the demo is full. Delete a file, or use Reset demo." });
      }
      if (raw) return new Response(raw, { status, headers: { 'Content-Type': 'application/octet-stream' } });
      return json(status, data);
    } catch (err) {
      if (!err || typeof err.status !== 'number') throw err;
      return json(err.status, { error: err.error });
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
