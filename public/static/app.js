'use strict';

(() => {
  const STATUS_LABELS = { planning: 'Planning', active: 'Active', done: 'Done' };
  // Mirrors src/security/access.js: file confidentiality and role clearance share this 1-5 scale.
  const CONFIDENTIALITY = { 1: 'Open', 2: 'Internal', 3: 'Confidential', 4: 'Restricted', 5: 'Secret' };
  const PRIVILEGED_ROLES = ['admin', 'ceo'];
  const AUTH_ENDPOINTS = ['/api/login', '/api/signup'];
  // Pages that are signed in to through the admin login.
  const CONSOLE_PAGES = ['admin', 'risk', 'crimguard'];

  // The static demo maps these server paths onto its own files; the real app uses them as they are.
  const route = (path) => (typeof window.RED_ROUTE === 'function' ? window.RED_ROUTE(path) : path);
  const go = (path) => location.assign(route(path));

  const $ = (selector, root = document) => root.querySelector(selector);

  // Tiny DOM builder. Children are appended as nodes or text, so user data is never parsed as HTML.
  function h(tag, props = {}, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value == null || value === false) continue;
      if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
      else if (key === 'class') el.className = value;
      else if (key === 'value') el.value = value;
      else el.setAttribute(key, value === true ? '' : value);
    }
    el.append(...children.flat().filter((child) => child != null && child !== false));
    return el;
  }

  let idCounter = 0;
  const uid = (prefix) => `${prefix}-${++idCounter}`;

  const plural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
  const people = (count) => (count === 1 ? '1 person' : `${count} people`);
  // English picks the article by sound. The built-in role names sound the way they are spelled ("an intern",
  // "an employee", "an admin", "a CEO"), so the first letter is enough.
  const withArticle = (word) => `${/^[aeio]/i.test(word) ? 'an' : 'a'} ${word}`;

  // The roles, from /api/roles once someone is signed in. Until then a role shows as its name.
  let roles = [];
  const roleLabel = (name) => roles.find((role) => role.name === name)?.label || name;
  const isPrivileged = (role) => PRIVILEGED_ROLES.includes(role);
  // "an intern", "a CEO": labels are lowercased mid-sentence unless they are initials.
  const roleNoun = (name) => {
    const label = roleLabel(name);
    return withArticle(label === label.toUpperCase() ? label : label.toLowerCase());
  };

  // "Not shared", "Shared with 1 role", "Shared with 2 roles and 1 person".
  function sharingSummary({ shared_roles: roleCount = 0, shared_people: peopleCount = 0 }) {
    const parts = [roleCount > 0 && plural(roleCount, 'role'), peopleCount > 0 && people(peopleCount)].filter(Boolean);
    return parts.length ? `Shared with ${parts.join(' and ')}` : 'Not shared';
  }
  const initials = (name) =>
    name.split(/\s+/).filter(Boolean).slice(0, 2).map((word) => [...word][0].toUpperCase()).join('') || '?';

  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KB', 'MB', 'GB'];
    let value = bytes / 1024;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    // Number() drops a trailing ".0", so a 1 MB limit reads "1 MB", not "1.0 MB".
    return `${value >= 10 ? Math.round(value) : Number(value.toFixed(1))} ${units[unit]}`;
  }

  // SQLite's datetime('now') is UTC with no zone marker.
  const parseSqlDate = (value) => new Date(`${String(value).replace(' ', 'T')}Z`);

  function formatDate(value) {
    const date = parseSqlDate(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
  }

  function formatDateTime(value) {
    const date = parseSqlDate(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit' });
  }

  const PASSWORD_HINT = 'At least 12 characters. A few unrelated words work well.';

  const statusOptions = (selected) =>
    Object.entries(STATUS_LABELS).map(([value, label]) => h('option', { value, selected: value === selected }, label));
  // The roles someone may hand out: those at or below their own clearance. A role above that still shows
  // when it is the current one, disabled, so the select reads correctly on a row like the CEO's.
  const roleOptions = (selected, maxClearance = 5) =>
    roles
      .filter((role) => role.clearance <= maxClearance || role.name === selected)
      .map((role) => h('option', { value: role.name, selected: role.name === selected, disabled: role.clearance > maxClearance }, role.label));

  // Five rising bars filled up to a level, and its name: a file's confidentiality or a role's clearance.
  function levelMeter(level, { text = CONFIDENTIALITY[level], showText = true } = {}) {
    return h('span', { class: `level level-${level}`, title: `${CONFIDENTIALITY[level]}, level ${level} of 5` },
      h('span', { class: 'level-bars', 'aria-hidden': 'true' }, [1, 2, 3, 4, 5].map((n) => h('span', { class: n <= level ? 'is-on' : null }))),
      h('span', { class: showText ? 'level-text' : 'sr-only' }, text));
  }

  let toastTimer;
  function toast(message, kind = 'ok') {
    const el = $('#toast');
    if (!el) return;
    el.textContent = message;
    el.dataset.kind = kind;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
  }

  async function failure(res, url) {
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && !AUTH_ENDPOINTS.includes(url)) {
      go(CONSOLE_PAGES.includes(document.body.dataset.page) ? '/admin/login' : '/login');
    } else if (res.status === 403 && data.code === 'password_change_required') {
      location.reload(); // the page asks for a new password as it loads
    } else if (res.status === 403 && data.code === 'not_privileged') {
      go('/dashboard'); // this account's admin role was removed while the page was open
    }
    const error = new Error(data.error || `Something went wrong (${res.status}). Try again.`);
    error.status = res.status;
    return error;
  }

  async function request(method, url, { body, headers = {} } = {}) {
    const res = await fetch(url, { method, headers, body });
    if (!res.ok) throw await failure(res, url);
    return res.status === 204 ? {} : res.json().catch(() => ({}));
  }

  const api = (method, url, body) =>
    request(method, url, method === 'GET' ? {} : { body: JSON.stringify(body || {}), headers: { 'Content-Type': 'application/json' } });

  // Uploads send the file's raw bytes; its name travels URL-encoded in a header.
  const sendFile = (method, url, file) =>
    request(method, url, {
      body: file,
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-File-Name': encodeURIComponent(file.name),
        'X-File-Type': file.type || 'application/octet-stream',
      },
    });

  // Fetches a file and saves it under its own name. Works the same with the server and the static demo.
  async function download(url, name) {
    const res = await fetch(url);
    if (!res.ok) throw await failure(res, url);
    const objectUrl = URL.createObjectURL(await res.blob());
    const link = h('a', { href: objectUrl, download: name, hidden: true });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
  }
  const downloadFile = (projectId, file) => download(`/api/projects/${projectId}/files/${file.id}/download`, file.name);

  // ---- form building blocks -----------------------------------------------------

  function field(label, control, { hint, forId } = {}) {
    const id = forId || control.id;
    return h('div', { class: 'field' },
      h('label', { class: 'field-label', for: id }, label),
      control,
      hint && h('p', { class: 'field-hint' }, hint));
  }

  function setReveal(button, show) {
    const input = document.getElementById(button.dataset.reveal);
    if (!input) return;
    input.type = show ? 'text' : 'password';
    button.textContent = show ? 'Hide' : 'Show';
    button.setAttribute('aria-pressed', String(show));
  }

  function initReveal() {
    for (const button of document.querySelectorAll('[data-reveal]')) button.setAttribute('aria-label', 'Show password');
    document.addEventListener('click', (event) => {
      const button = event.target.closest('[data-reveal]');
      if (button) setReveal(button, button.getAttribute('aria-pressed') !== 'true');
    });
  }

  function passwordField(label, name, { autocomplete = 'new-password', hint } = {}) {
    const input = h('input', {
      id: uid(name),
      name,
      type: 'password',
      autocomplete,
      minlength: autocomplete === 'current-password' ? null : 12,
      maxlength: 256,
      required: true,
    });
    const reveal = h('button', { class: 'reveal', type: 'button', 'data-reveal': input.id, 'aria-pressed': 'false', 'aria-label': 'Show password' }, 'Show');
    return field(label, h('div', { class: 'input-wrap' }, input, reveal), { hint, forId: input.id });
  }

  // A modal form: title, note, fields, an inline error, Cancel and a submit button.
  // With `required`, Escape doesn't close it and the secondary button runs `onCancel` instead.
  function formDialog({ title, note = '', fields, submitLabel, onSubmit, required = false, cancelLabel = 'Cancel', onCancel }) {
    const titleEl = h('h2', { class: 'dialog-title', id: uid('dialog-title') }, title);
    const noteEl = h('p', { class: 'dialog-note' }, note);
    const error = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const cancel = h('button', { class: 'btn btn-secondary', type: 'button' }, cancelLabel);
    const submit = h('button', { class: 'btn btn-primary', type: 'submit' }, submitLabel);
    const form = h('form', { class: 'dialog-form' },
      h('div', { class: 'dialog-head' }, titleEl, noteEl),
      h('div', { class: 'dialog-body' }, fields, error),
      h('div', { class: 'dialog-actions' }, cancel, submit));
    const dialog = h('dialog', { class: 'dialog', 'aria-labelledby': titleEl.id }, form);
    document.body.append(dialog);

    // Clear typed values as soon as the dialog is done with. Cancel and a successful save clear right away,
    // because Chrome delivers the close event only on the next rendered frame; the listener covers Escape.
    function clear() {
      form.reset();
      error.hidden = true;
      error.textContent = '';
      for (const button of form.querySelectorAll('[data-reveal]')) setReveal(button, false);
    }
    function close() {
      dialog.close();
      clear();
    }
    let done = false;
    cancel.addEventListener('click', onCancel || close);
    if (required) dialog.addEventListener('cancel', (event) => event.preventDefault());
    dialog.addEventListener('close', () => {
      // Browsers let a repeated Escape close even a dialog that cancels it; a required one comes straight back.
      if (required && !done) return dialog.showModal();
      if (!dialog.open) clear(); // a late event must not wipe a dialog that was already reopened
    });

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      submit.disabled = true;
      error.hidden = true;
      try {
        await onSubmit(form);
        done = true;
        close();
      } catch (err) {
        error.textContent = err.message;
        error.hidden = false;
      } finally {
        submit.disabled = false;
      }
    });

    return {
      open({ title: nextTitle, note: nextNote, submitLabel: nextSubmit, values = {} } = {}) {
        done = false;
        clear();
        if (nextTitle) titleEl.textContent = nextTitle;
        if (nextNote != null) noteEl.textContent = nextNote;
        if (nextSubmit) submit.textContent = nextSubmit;
        for (const [name, value] of Object.entries(values)) form.elements[name].value = value;
        dialog.showModal();
      },
    };
  }

  // ---- sign in and sign up --------------------------------------------------------

  function initAuthForm(form, endpoint, extra = {}) {
    const error = form.querySelector('.form-error');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      error.hidden = true;
      try {
        const { redirect } = await api('POST', endpoint, { ...Object.fromEntries(new FormData(form)), ...extra });
        go(redirect);
      } catch (err) {
        error.textContent = err.message;
        error.hidden = false;
        button.disabled = false;
      }
    });
  }

  // ---- signed-in shell: account menu and your own password ------------------------

  const logOut = async () => {
    await api('POST', '/api/logout').catch(() => {});
    go('/');
  };

  // With `forced`, the person signed in with a password an admin chose and must replace it before continuing.
  function accountDialog(user, { forced = false, onDone } = {}) {
    // A username field lets password managers update the right saved login.
    const username = h('input', { type: 'email', name: 'username', autocomplete: 'username', readonly: true, hidden: true });
    username.defaultValue = user.email;

    return formDialog({
      title: forced ? 'Choose a new password' : 'Change your password',
      note: forced
        ? 'An admin set the password you just used. Replace it with one only you know to continue.'
        : 'You stay signed in here. Other devices signed in to your account are signed out.',
      submitLabel: forced ? 'Set new password' : 'Change password',
      required: forced,
      cancelLabel: forced ? 'Log out' : 'Cancel',
      onCancel: forced ? logOut : undefined,
      fields: [
        username,
        passwordField(forced ? 'Password you signed in with' : 'Current password', 'currentPassword', { autocomplete: 'current-password' }),
        passwordField('New password', 'newPassword', { hint: PASSWORD_HINT }),
        passwordField('Confirm new password', 'confirmPassword'),
      ],
      async onSubmit(form) {
        const { currentPassword, newPassword, confirmPassword } = form.elements;
        if (newPassword.value !== confirmPassword.value) {
          confirmPassword.focus();
          throw new Error("The new passwords don't match.");
        }
        await api('PATCH', '/api/me/password', { currentPassword: currentPassword.value, newPassword: newPassword.value });
        toast(forced ? 'New password set' : 'Password changed');
        if (onDone) onDone();
      },
    });
  }

  function profileDialog(onSaved) {
    const email = h('p', { class: 'profile-email' });
    const dialog = formDialog({
      title: 'Your profile',
      note: 'Admins see your name and email. The rest is for you and your team.',
      submitLabel: 'Save profile',
      fields: [
        field('Full name', h('input', { id: uid('profile-name'), name: 'name', autocomplete: 'name', maxlength: 80, required: true })),
        h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Email'), email),
        field('Job title', h('input', { id: uid('profile-title'), name: 'jobTitle', autocomplete: 'organization-title', maxlength: 80 }), { hint: 'Optional.' }),
        field('Team or organization', h('input', { id: uid('profile-org'), name: 'organization', autocomplete: 'organization', maxlength: 80 }), { hint: 'Optional.' }),
        field('About you', h('textarea', { id: uid('profile-bio'), name: 'bio', maxlength: 500, rows: 3 }), { hint: 'Optional. Up to 500 characters.' }),
      ],
      async onSubmit(form) {
        const { profile } = await api('PATCH', '/api/me/profile', Object.fromEntries(new FormData(form)));
        toast('Profile saved');
        onSaved(profile);
      },
    });

    return {
      async open() {
        try {
          const { profile } = await api('GET', '/api/me/profile');
          email.textContent = profile.email;
          dialog.open({ values: { name: profile.name, jobTitle: profile.jobTitle, organization: profile.organization, bio: profile.bio } });
        } catch (err) {
          toast(err.message, 'error');
        }
      },
    };
  }

  // Fills in the top bar and account menu. Resolves once the person is free to use the page,
  // which, for someone who must replace an admin-set password, is after they've done so.
  async function initShell() {
    const menu = $('#account-menu');
    const button = $('#account-button');
    if (!('popover' in HTMLElement.prototype)) {
      // Browsers without the popover API get a plain toggle.
      menu.hidden = true;
      button.addEventListener('click', () => { menu.hidden = !menu.hidden; });
    }
    const hideMenu = () => (menu.hidePopover ? menu.hidePopover() : (menu.hidden = true));

    $('#logout').addEventListener('click', logOut);

    const { user } = await api('GET', '/api/me');
    const showIdentity = ({ name, email }) => {
      $('#account-name').textContent = name;
      $('#account-avatar').textContent = initials(name);
      button.setAttribute('aria-label', `Account menu for ${name}`);
      $('#menu-name').textContent = name;
      $('#menu-email').textContent = email;
    };
    showIdentity(user);

    const account = accountDialog(user);
    $('#change-password').addEventListener('click', () => {
      hideMenu();
      account.open();
    });

    const profile = profileDialog((saved) => {
      user.name = saved.name;
      showIdentity(saved);
    });
    $('#edit-profile').addEventListener('click', () => {
      hideMenu();
      profile.open();
    });

    if (user.mustChangePassword) {
      await new Promise((resolve) => accountDialog(user, { forced: true, onDone: resolve }).open());
      user.mustChangePassword = false;
    }

    // Read only once the password is sorted out: until then the API refuses everything else.
    ({ roles } = await api('GET', '/api/roles'));
    const badge = $('#role-badge');
    if (badge) {
      badge.textContent = roleLabel(user.role);
      badge.classList.toggle('is-admin', isPrivileged(user.role));
      badge.hidden = false;
    }
    $('#account-avatar').classList.toggle('is-admin', isPrivileged(user.role));
    return { me: user, account };
  }

  function emptyState(title, text, action) {
    return h('div', { class: 'empty' },
      h('h2', {}, title),
      h('p', {}, text),
      action && h('button', { class: 'btn btn-primary', type: 'button', onclick: action.run }, action.label));
  }

  // ---- projects (the user dashboard and an admin's own projects) ------------------

  function mountProjects(root, me) {
    let projects = [];
    let filter = 'all';
    let loaded = false;
    let editing = null;

    const dialog = formDialog({
      title: 'New project',
      submitLabel: 'Create project',
      fields: [
        h('div', { class: 'field-pair' },
          field('Name', h('input', { id: uid('project-name'), name: 'name', maxlength: 120, required: true, placeholder: 'Customer onboarding flow' })),
          field('Status', h('select', { id: uid('project-status'), name: 'status' }, statusOptions('planning')))),
        field('Description', h('textarea', { id: uid('project-description'), name: 'description', maxlength: 2000, rows: 4, placeholder: 'What is this project for, and what does done look like?' }), { hint: 'Optional.' }),
      ],
      async onSubmit(form) {
        const data = Object.fromEntries(new FormData(form));
        if (editing) {
          const { project } = await api('PATCH', `/api/projects/${editing.id}`, data);
          projects = [project, ...projects.filter((p) => p.id !== project.id)];
          drawer.sync(projects);
          toast('Project saved');
        } else {
          const { project } = await api('POST', '/api/projects', data);
          projects.unshift(project);
          toast('Project created');
        }
        render();
      },
    });

    const openNew = () => {
      editing = null;
      dialog.open({ title: 'New project', note: 'Only you, admins and the CEO can see your projects.', submitLabel: 'Create project' });
    };
    const openEdit = (project) => {
      editing = project;
      dialog.open({
        title: 'Edit project',
        note: '',
        submitLabel: 'Save changes',
        values: { name: project.name, status: project.status, description: project.description },
      });
    };
    for (const button of document.querySelectorAll('[data-new-project]')) button.addEventListener('click', openNew);

    const drawer = projectDrawer({
      me,
      onEdit: (project) => openEdit(projects.find((p) => p.id === project.id) || project),
      // File changes move a project to the top and change its file count, so reload the list.
      onFilesChanged: () =>
        api('GET', '/api/projects')
          .then((data) => {
            projects = data.projects;
            render();
            drawer.sync(projects);
          })
          .catch((err) => toast(err.message, 'error')),
    });

    const filterBar = h('div', { class: 'filter', role: 'group', 'aria-label': 'Filter by status' },
      ['all', 'active', 'planning', 'done'].map((key) =>
        h('button', { type: 'button', 'data-status': key, 'aria-pressed': String(key === filter), onclick: () => { filter = key; render(); } },
          key === 'all' ? 'All' : STATUS_LABELS[key],
          h('span', { class: 'count' }))));
    const surface = h('div', { class: 'surface' });
    root.replaceChildren(h('div', { class: 'toolbar' }, filterBar), surface);

    function render() {
      const counts = { all: projects.length, planning: 0, active: 0, done: 0 };
      for (const project of projects) counts[project.status] += 1;
      for (const button of filterBar.querySelectorAll('button')) {
        button.setAttribute('aria-pressed', String(button.dataset.status === filter));
        button.querySelector('.count').textContent = loaded ? counts[button.dataset.status] : '';
      }

      if (!loaded) {
        surface.replaceChildren(h('div', { class: 'empty' }, h('p', {}, 'Loading projects…')));
      } else if (!projects.length) {
        surface.replaceChildren(emptyState('No projects yet', 'Create a project to start tracking it, then add its files.', { label: 'New project', run: openNew }));
      } else {
        const shown = filter === 'all' ? projects : projects.filter((project) => project.status === filter);
        surface.replaceChildren(shown.length
          ? h('ul', { class: 'project-list' }, shown.map(row))
          : emptyState(`No ${STATUS_LABELS[filter].toLowerCase()} projects`, 'Choose another filter to see the rest of your projects.'));
      }
    }

    function row(project) {
      return h('li', { class: 'project-row' },
        h('span', { class: `status status-${project.status}` }, STATUS_LABELS[project.status]),
        h('div', { class: 'project-main' },
          h('p', { class: 'project-name' },
            h('button', { class: 'project-open', type: 'button', 'aria-haspopup': 'dialog', onclick: () => drawer.open(project) }, project.name)),
          project.description && h('p', { class: 'project-desc' }, project.description)),
        h('span', { class: 'project-updated' },
          `Updated ${formatDate(project.updated_at)}`,
          project.file_count > 0 && h('span', { class: 'project-files' }, `, ${plural(project.file_count, 'file')}`)),
        h('div', { class: 'row-actions' },
          h('button', { class: 'btn btn-quiet btn-sm', type: 'button', 'aria-label': `Edit ${project.name}`, onclick: () => openEdit(project) }, 'Edit'),
          h('button', { class: 'btn btn-quiet btn-danger btn-sm', type: 'button', 'aria-label': `Delete ${project.name}`, onclick: () => remove(project) }, 'Delete')));
    }

    async function remove(project) {
      if (!confirm(`Delete "${project.name}"? This can't be undone.`)) return;
      try {
        await api('DELETE', `/api/projects/${project.id}`);
        projects = projects.filter((p) => p.id !== project.id);
        render();
        drawer.sync(projects);
        toast('Project deleted');
      } catch (err) {
        toast(err.message, 'error');
      }
    }

    render();
    api('GET', '/api/projects')
      .then((data) => {
        projects = data.projects;
        loaded = true;
        render();
      })
      .catch((err) => toast(err.message, 'error'));
  }

  // ---- people & roles (admins only) ------------------------------------------------

  // ---- project panel: details and files ---------------------------------------------

  function closeIcon() {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    for (const [key, value] of Object.entries({ width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true' })) svg.setAttribute(key, value);
    const path = document.createElementNS(ns, 'path');
    for (const [key, value] of Object.entries({ d: 'M4 4l8 8M12 4l-8 8', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.8, 'stroke-linecap': 'round' })) path.setAttribute(key, value);
    svg.append(path);
    return svg;
  }

  function extensionOf(name) {
    const dot = name.lastIndexOf('.');
    return dot > 0 && dot < name.length - 1 ? name.slice(dot + 1, dot + 5).toLowerCase() : 'file';
  }

  function projectDrawer({ me, onEdit, onFilesChanged }) {
    let project = null;
    let files = [];
    let loading = false;
    let maxFileBytes = 10 * 1024 * 1024;
    let renamingId = null;
    let replaceTarget = null;
    let dragDepth = 0;
    const busy = new Set();
    const errors = new Map();
    const uploads = [];
    // Admins and the CEO choose who can see a file; everyone else sees what was chosen.
    const access = isPrivileged(me.role) ? accessDialog(me) : null;

    const titleEl = h('h2', { class: 'drawer-title', id: uid('drawer-title') });
    const meta = h('div', { class: 'drawer-meta' });
    const description = h('p', { class: 'drawer-desc' });
    const summary = h('span', { class: 'files-summary' });
    const limitHint = h('span', { class: 'field-hint' });
    const list = h('div');
    const picker = h('input', { type: 'file', multiple: true, hidden: true });
    const replacePicker = h('input', { type: 'file', hidden: true });
    const dropzone = h('div', { class: 'dropzone' },
      h('span', {}, 'Drag in as many files as you like, or ', h('button', { class: 'link-button', type: 'button', onclick: () => picker.click() }, 'choose several at once')),
      limitHint);

    const dialog = h('dialog', { class: 'drawer', 'aria-labelledby': titleEl.id },
      h('div', { class: 'drawer-head' },
        h('div', {}, titleEl, meta),
        h('div', { class: 'drawer-head-actions' },
          h('button', { class: 'btn btn-secondary btn-sm', type: 'button', onclick: () => project && onEdit(project) }, 'Edit details'),
          h('button', { class: 'icon-button', type: 'button', 'aria-label': 'Close', onclick: () => dialog.close() }, closeIcon()))),
      h('div', { class: 'drawer-body' },
        description,
        h('section', { class: 'files', 'aria-labelledby': uid('files-title') },
          h('div', { class: 'files-head' },
            h('div', { class: 'files-title' }, h('h3', {}, 'Files'), summary),
            h('button', { class: 'btn btn-secondary btn-sm', type: 'button', onclick: () => picker.click() }, 'Add files')),
          dropzone,
          list,
          picker,
          replacePicker)));
    dialog.querySelector('.files-head h3').id = dialog.querySelector('.files').getAttribute('aria-labelledby');
    document.body.append(dialog);

    // The whole panel accepts dropped files, so a near miss doesn't open the file in the browser.
    dialog.addEventListener('dragenter', (event) => {
      if (!event.dataTransfer?.types.includes('Files')) return;
      event.preventDefault();
      dragDepth += 1;
      dropzone.classList.add('is-dragging');
    });
    dialog.addEventListener('dragover', (event) => event.preventDefault());
    dialog.addEventListener('dragleave', () => {
      dragDepth = Math.max(0, dragDepth - 1);
      if (!dragDepth) dropzone.classList.remove('is-dragging');
    });
    dialog.addEventListener('drop', (event) => {
      event.preventDefault();
      dragDepth = 0;
      dropzone.classList.remove('is-dragging');
      if (event.dataTransfer?.files.length) upload([...event.dataTransfer.files]);
    });

    picker.addEventListener('change', () => {
      const chosen = [...picker.files];
      picker.value = '';
      upload(chosen);
    });
    replacePicker.addEventListener('change', () => {
      const chosen = replacePicker.files[0];
      const target = replaceTarget;
      replacePicker.value = '';
      replaceTarget = null;
      if (chosen && target) replace(target, chosen);
    });

    dialog.addEventListener('close', () => {
      project = null;
      files = [];
      renamingId = null;
      errors.clear();
    });

    const tooLarge = (file) => `${file.name} is ${formatBytes(file.size)}. Files can be up to ${formatBytes(maxFileBytes)}.`;
    const isShowing = (projectId) => project && project.id === projectId;

    // Every chosen file is listed straight away, then sent one after another.
    async function upload(chosen) {
      if (!project) return;
      const projectId = project.id;
      const tooBig = chosen.filter((file) => file.size > maxFileBytes);
      if (tooBig.length) toast(tooBig.length === 1 ? tooLarge(tooBig[0]) : `${plural(tooBig.length, 'file')} are over ${formatBytes(maxFileBytes)} and were skipped.`, 'error');
      const queue = chosen
        .filter((file) => file.size <= maxFileBytes)
        .map((file) => ({ projectId, file, name: file.name, size: file.size, started: false }));
      if (!queue.length) return;
      uploads.push(...queue);
      render();

      let saved = 0;
      let lastError = null;
      for (const pending of queue) {
        pending.started = true;
        render();
        try {
          const { file } = await sendFile('POST', `/api/projects/${projectId}/files`, pending.file);
          if (isShowing(projectId)) files = [file, ...files];
          saved += 1;
        } catch (err) {
          lastError = err;
        } finally {
          uploads.splice(uploads.indexOf(pending), 1);
          render();
        }
      }

      if (saved) onFilesChanged();
      if (!lastError) toast(saved === 1 ? `Uploaded ${queue[0].name}` : `Uploaded ${saved} files`);
      else if (queue.length === 1) toast(lastError.message, 'error');
      else toast(`Uploaded ${saved} of ${queue.length} files. ${lastError.message}`, 'error');
    }

    function updateAccess(fileId, saved) {
      files = files.map((file) => (file.id === fileId
        ? { ...file, confidentiality: saved.file.confidentiality, shared_roles: saved.roles.length, shared_people: saved.people.length }
        : file));
      render();
    }

    async function withBusy(file, work) {
      const projectId = project.id;
      busy.add(file.id);
      errors.delete(file.id);
      render();
      try {
        await work(projectId);
        onFilesChanged();
      } catch (err) {
        errors.set(file.id, err.message);
      } finally {
        busy.delete(file.id);
        render();
      }
    }

    function replace(file, chosen) {
      if (chosen.size > maxFileBytes) {
        toast(tooLarge(chosen), 'error');
        return;
      }
      withBusy(file, async (projectId) => {
        const { file: saved } = await sendFile('PUT', `/api/projects/${projectId}/files/${file.id}/content`, chosen);
        if (isShowing(projectId)) files = [saved, ...files.filter((f) => f.id !== saved.id)];
        toast(`Uploaded a new version of ${saved.name}`);
      });
    }

    function rename(file, name) {
      withBusy(file, async (projectId) => {
        const { file: saved } = await api('PATCH', `/api/projects/${projectId}/files/${file.id}`, { name });
        if (isShowing(projectId)) files = files.map((f) => (f.id === saved.id ? saved : f));
        renamingId = null;
        toast(`Renamed to ${saved.name}`);
      });
    }

    function remove(file) {
      if (!confirm(`Delete ${file.name}? This can't be undone.`)) return;
      withBusy(file, async (projectId) => {
        await api('DELETE', `/api/projects/${projectId}/files/${file.id}`);
        if (isShowing(projectId)) files = files.filter((f) => f.id !== file.id);
        toast(`Deleted ${file.name}`);
      });
    }

    function stopRenaming(file) {
      renamingId = null;
      errors.delete(file.id);
      render();
    }

    function renderProject() {
      titleEl.textContent = project.name;
      meta.replaceChildren(
        h('span', { class: `status status-${project.status}` }, STATUS_LABELS[project.status]),
        h('span', {}, `Updated ${formatDate(project.updated_at)}`));
      description.textContent = project.description || 'No description yet.';
      description.classList.toggle('is-empty', !project.description);
    }

    function fileRow(file) {
      const isBusy = busy.has(file.id);
      const error = errors.get(file.id);
      const badge = h('span', { class: 'file-badge', 'aria-hidden': 'true' }, extensionOf(file.name));

      if (renamingId === file.id) {
        const input = h('input', { value: file.name, maxlength: 255, required: true, 'aria-label': `New name for ${file.name}` });
        const form = h('form', { class: 'file-rename' },
          input,
          h('button', { class: 'btn btn-primary btn-sm', type: 'submit', disabled: isBusy }, 'Save'),
          h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => stopRenaming(file) }, 'Cancel'));
        form.addEventListener('submit', (event) => {
          event.preventDefault();
          if (input.value.trim() === file.name) stopRenaming(file);
          else rename(file, input.value);
        });
        input.addEventListener('keydown', (event) => {
          if (event.key !== 'Escape') return;
          event.preventDefault(); // cancel the rename, not the whole panel
          stopRenaming(file);
        });
        queueMicrotask(() => {
          if (!input.isConnected || document.activeElement === input) return;
          input.focus();
          const dot = file.name.lastIndexOf('.');
          input.setSelectionRange(0, dot > 0 ? dot : file.name.length); // select the name, not the extension
        });
        return h('li', { class: 'file-row is-renaming' }, badge, h('div', { class: 'file-main' }, form),
          error && h('p', { class: 'file-error', role: 'alert' }, error));
      }

      const action = (label, ariaLabel, onclick, extra = '') =>
        h('button', { class: `btn btn-quiet btn-sm${extra}`, type: 'button', disabled: isBusy, 'aria-label': ariaLabel, onclick }, label);
      const canManageAccess = access && file.confidentiality <= me.clearance;
      return h('li', { class: isBusy ? 'file-row is-busy' : 'file-row', 'aria-busy': isBusy ? 'true' : null },
        badge,
        h('div', { class: 'file-main' },
          h('p', { class: 'file-name', title: file.name }, file.name),
          h('p', { class: 'file-meta' }, `${formatBytes(file.size)}, updated ${formatDate(file.updated_at)}`),
          h('p', { class: 'file-access' }, levelMeter(file.confidentiality), h('span', {}, sharingSummary(file)))),
        h('div', { class: 'file-actions' },
          canManageAccess && action('Access', `Choose who can see ${file.name}`, () => access.open(file, (saved) => updateAccess(file.id, saved))),
          action('Download', `Download ${file.name}`, () => downloadFile(project.id, file).catch((err) => toast(err.message, 'error'))),
          action('Rename', `Rename ${file.name}`, () => {
            renamingId = file.id;
            errors.delete(file.id);
            render();
          }),
          action('Replace', `Replace ${file.name} with a new version`, () => {
            replaceTarget = file;
            replacePicker.click();
          }),
          action('Delete', `Delete ${file.name}`, () => remove(file), ' btn-danger')),
        error && h('p', { class: 'file-error', role: 'alert' }, error));
    }

    function render() {
      if (!project) return;
      const total = files.reduce((sum, file) => sum + file.size, 0);
      summary.textContent = loading ? 'Loading files…' : files.length ? `${plural(files.length, 'file')}, ${formatBytes(total)}` : 'No files yet';
      limitHint.textContent = `Up to ${formatBytes(maxFileBytes)} each`;
      const rows = [
        // Only uploads for the project on screen; switching projects mid-upload must not show them elsewhere.
        ...uploads.filter((pending) => pending.projectId === project.id).map((pending) =>
          h('li', { class: 'file-row is-busy', 'aria-busy': 'true' },
            h('span', { class: 'file-badge', 'aria-hidden': 'true' }, extensionOf(pending.name)),
            h('div', { class: 'file-main' },
              h('p', { class: 'file-name', title: pending.name }, pending.name),
              h('p', { class: 'file-meta' }, pending.started ? `Uploading ${formatBytes(pending.size)}…` : `Waiting to upload, ${formatBytes(pending.size)}`)))),
        ...files.map(fileRow),
      ];
      list.replaceChildren(...(rows.length ? [h('ul', { class: 'file-list' }, rows)] : []));
    }

    return {
      async open(next) {
        project = next;
        files = [];
        renamingId = null;
        errors.clear();
        loading = true;
        renderProject();
        render();
        if (!dialog.open) dialog.showModal();
        try {
          const data = await api('GET', `/api/projects/${next.id}/files`);
          if (!isShowing(next.id)) return;
          files = data.files;
          if (data.maxFileBytes) maxFileBytes = data.maxFileBytes;
        } catch (err) {
          toast(err.message, 'error');
        } finally {
          if (isShowing(next.id)) {
            loading = false;
            render();
          }
        }
      },
      // Keeps the open panel in step with the project list: new details, or closed if the project is gone.
      sync(projects) {
        if (!project) return;
        const fresh = projects.find((p) => p.id === project.id);
        if (!fresh) {
          dialog.close();
          return;
        }
        project = fresh;
        renderProject();
      },
    };
  }

  // ---- who can see a file (admins and the CEO) --------------------------------------------

  // One file's confidentiality, and the roles and people it is shared with. The server applies the same
  // limits; this only avoids offering choices it would refuse.
  function accessDialog(me) {
    let current = null;
    let directory = null; // everyone with an account, loaded the first time the dialog opens

    const levels = h('div', { class: 'level-picker' });
    const roleList = h('div', { class: 'check-list' });
    const search = h('input', { class: 'search', id: uid('access-search'), type: 'search', placeholder: 'Search by name or email', 'aria-label': 'Search people', autocomplete: 'off' });
    const peopleList = h('div', { class: 'check-list check-list-scroll' });
    const outcome = h('p', { class: 'access-outcome', 'aria-live': 'polite' });

    const dialog = formDialog({
      title: 'Who can see this file',
      submitLabel: 'Save access',
      fields: [
        h('fieldset', { class: 'fieldset' }, h('legend', { class: 'field-label' }, 'Confidentiality'), levels),
        h('fieldset', { class: 'fieldset' },
          h('legend', { class: 'field-label' }, 'Share with roles'),
          h('p', { class: 'field-hint' }, "Everyone in a role can open the file while the role's clearance covers its confidentiality."),
          roleList),
        h('fieldset', { class: 'fieldset' },
          h('legend', { class: 'field-label' }, 'Share with people'),
          h('p', { class: 'field-hint' }, 'People you pick can open it at any confidentiality.'),
          search,
          peopleList),
        outcome,
      ],
      async onSubmit(form) {
        const data = new FormData(form);
        const saved = await api('PUT', `/api/files/${current.file.id}/access`, {
          confidentiality: Number(data.get('confidentiality')),
          roles: data.getAll('role').map(Number),
          people: data.getAll('person').map(Number),
        });
        toast(`Saved who can see ${saved.file.name}`);
        if (current.onSaved) current.onSaved(saved);
      },
    });
    const form = levels.closest('form');
    form.closest('dialog').classList.add('dialog-wide');
    form.addEventListener('change', refresh);
    search.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') event.preventDefault(); // searching, not saving
    });
    search.addEventListener('input', () => {
      const term = search.value.trim().toLowerCase();
      for (const row of peopleList.children) row.hidden = Boolean(term) && !row.dataset.search.includes(term);
    });

    function checkRow({ name, value, checked, title, meta, extra = {} }) {
      const id = uid(name);
      return h('label', { class: 'check-row', for: id, ...extra },
        h('input', { type: 'checkbox', id, name, value, checked }),
        h('span', { class: 'check-main' }, h('span', { class: 'check-title' }, title), h('span', { class: 'check-meta' }, meta)),
        h('span', { class: 'check-note' }));
    }

    function render(access) {
      const level = access.file.confidentiality;
      levels.replaceChildren(...[1, 2, 3, 4, 5].map((n) => {
        const id = uid('level');
        const locked = n > me.clearance;
        return h('label', { class: 'level-option', for: id, title: locked ? `Only the CEO can mark a file ${CONFIDENTIALITY[n]}` : null },
          h('input', { type: 'radio', id, name: 'confidentiality', value: n, checked: n === level, disabled: locked, required: true }),
          h('span', { class: 'level-option-body' }, levelMeter(n, { showText: false }), h('span', {}, CONFIDENTIALITY[n])));
      }));

      // Admins and the CEO see files by their own clearance, so sharing with those roles would change nothing.
      const grantedRoles = new Set(access.roles.map((role) => role.id));
      roleList.replaceChildren(...roles.filter((role) => !isPrivileged(role.name)).map((role) => checkRow({
        name: 'role',
        value: role.id,
        checked: grantedRoles.has(role.id),
        title: role.label,
        meta: `Clearance ${role.clearance}, ${people(role.member_count || 0)}`,
        extra: { 'data-clearance': role.clearance },
      })));

      const grantedPeople = new Set(access.people.map((person) => person.id));
      const candidates = directory
        .filter((person) => person.id !== access.file.owner.id)
        .sort((a, b) => Number(grantedPeople.has(b.id)) - Number(grantedPeople.has(a.id)) || a.name.localeCompare(b.name));
      peopleList.replaceChildren(...candidates.map((person) => checkRow({
        name: 'person',
        value: person.id,
        checked: grantedPeople.has(person.id),
        title: person.name,
        meta: `${person.email}, ${roleLabel(person.role)}`,
        extra: { 'data-search': `${person.name} ${person.email}`.toLowerCase() },
      })));
    }

    // Flags roles that can't open the file at the chosen level, and says what saving will do.
    function refresh() {
      const level = Number(new FormData(form).get('confidentiality'));
      let roleCount = 0;
      for (const row of roleList.children) {
        const checked = row.querySelector('input').checked;
        const blocked = checked && Number(row.dataset.clearance) < level;
        row.classList.toggle('is-blocked', blocked);
        row.querySelector('.check-note').textContent = blocked ? `Can't open ${CONFIDENTIALITY[level]} files` : '';
        if (checked) roleCount += 1;
      }
      const personCount = peopleList.querySelectorAll('input:checked').length;
      const always = level <= 4 ? 'its owner, admins and the CEO' : 'its owner and the CEO';
      outcome.textContent = `${sharingSummary({ shared_roles: roleCount, shared_people: personCount })}. Besides that, ${always} can always open it.`;
    }

    return {
      async open(file, onSaved) {
        try {
          const [access, everyone] = await Promise.all([
            api('GET', `/api/files/${file.id}/access`),
            directory || api('GET', '/api/admin/users').then((data) => data.users),
          ]);
          directory = everyone;
          current = { file: access.file, onSaved };
          render(access);
          dialog.open({
            title: `Who can see ${access.file.name}`,
            note: `In ${access.file.owner.name}'s project ${access.file.project.name}.`,
          });
          refresh();
        } catch (err) {
          toast(err.message, 'error');
        }
      },
    };
  }

  // ---- files shared with you --------------------------------------------------------------

  function mountShared(root, me) {
    let files = [];
    let loaded = false;
    const surface = h('div', { class: 'surface table-wrap' });
    root.replaceChildren(surface);

    const th = (label, className) => h('th', { scope: 'col', class: className || null }, label);

    function render() {
      if (!loaded) {
        surface.replaceChildren(h('div', { class: 'empty' }, h('p', {}, 'Loading shared files…')));
        return;
      }
      if (!files.length) {
        surface.replaceChildren(emptyState('Nothing shared with you yet', 'When an admin or the CEO shares a file with you or your role, it shows up here.'));
        return;
      }
      surface.replaceChildren(h('table', { class: 'table' },
        h('thead', {}, h('tr', {},
          th('File'), th('Confidentiality'), th('From'), th('Shared with'), th('Size', 'num'), th('Updated'),
          th(h('span', { class: 'sr-only' }, 'Actions')))),
        h('tbody', {}, files.map((file) => h('tr', {},
          h('td', {}, h('div', { class: 'shared-file' },
            h('span', { class: 'file-badge', 'aria-hidden': 'true' }, extensionOf(file.name)),
            h('span', { class: 'shared-name', title: file.name }, file.name))),
          h('td', {}, levelMeter(file.confidentiality)),
          h('td', { class: 'wrap' }, h('div', { class: 'person-text' },
            h('span', {}, file.owner_name),
            h('span', { class: 'person-email' }, file.project_name))),
          h('td', { class: 'muted' }, file.by_name ? 'You' : `Everyone who is ${roleNoun(me.role)}`),
          h('td', { class: 'num' }, formatBytes(file.size)),
          h('td', { class: 'date' }, formatDate(file.updated_at)),
          h('td', {}, h('div', { class: 'row-actions' },
            h('button', {
              class: 'btn btn-secondary btn-sm',
              type: 'button',
              'aria-label': `Download ${file.name}`,
              onclick: () => download(`/api/files/${file.id}/download`, file.name).catch((err) => toast(err.message, 'error')),
            }, 'Download'))))))));
    }

    async function load() {
      try {
        ({ files } = await api('GET', '/api/files/shared'));
        loaded = true;
      } catch (err) {
        toast(err.message, 'error');
      }
      render();
    }

    render();
    return { load };
  }

  // ---- people & roles (admins and the CEO) ------------------------------------------------

  function mountPeople(me, account, onChange = () => {}) {
    const rows = $('#user-rows');
    const summary = $('#people-summary');
    const search = $('#user-search');
    const roleFilter = $('#role-filter');
    let users = [];
    let loaded = false;
    let role = 'all';
    let resetTarget = null;
    // Anyone up to your own clearance: admins manage admins and below, and only the CEO reaches a CEO.
    const canManage = (user) => user.clearance <= me.clearance;
    const addRole = h('select', { id: uid('person-role'), name: 'role' });
    const filterButton = (value, label, count) =>
      h('button', { type: 'button', 'data-role': value, 'aria-pressed': String(value === role) }, label, h('span', { class: 'count' }, String(count)));

    const addDialog = formDialog({
      title: 'Add a person',
      note: 'Share this password with them directly. They choose their own the first time they sign in.',
      submitLabel: 'Add person',
      fields: [
        field('Full name', h('input', { id: uid('person-name'), name: 'name', maxlength: 80, autocomplete: 'off', required: true })),
        field('Email', h('input', { id: uid('person-email'), name: 'email', type: 'email', autocomplete: 'off', required: true })),
        h('div', { class: 'field-pair' },
          passwordField('Password', 'password', { hint: 'At least 12 characters.' }),
          field('Role', addRole)),
      ],
      async onSubmit(form) {
        const { user } = await api('POST', '/api/admin/users', Object.fromEntries(new FormData(form)));
        toast(`Added ${user.name} as ${roleNoun(user.role)}`);
        await load();
        onChange();
      },
    });

    const resetDialog = formDialog({
      title: 'Reset password',
      submitLabel: 'Reset password',
      fields: [passwordField('New password', 'password', { hint: 'At least 12 characters.' })],
      async onSubmit(form) {
        const target = resetTarget;
        await api('PATCH', `/api/admin/users/${target.id}/password`, { password: form.elements.password.value });
        toast(`Password reset for ${target.name}`);
      },
    });

    $('#add-person').addEventListener('click', () => {
      addRole.replaceChildren(...roleOptions('employee', me.clearance));
      addDialog.open();
    });
    search.addEventListener('input', render);
    roleFilter.addEventListener('click', (event) => {
      const button = event.target.closest('button[data-role]');
      if (!button) return;
      role = button.dataset.role;
      render();
    });

    async function load() {
      try {
        ({ users } = await api('GET', '/api/admin/users'));
        loaded = true;
        render();
      } catch (err) {
        toast(err.message, 'error');
      }
    }

    function render() {
      if (!loaded) return;
      const withConsole = users.filter((user) => isPrivileged(user.role)).length;
      summary.textContent = `${people(users.length)}, ${withConsole} with the admin console`;

      // One filter for each role someone holds, highest clearance first. Rebuilt, so focus is put back.
      const counts = new Map();
      for (const user of users) counts.set(user.role, (counts.get(user.role) || 0) + 1);
      if (role !== 'all' && !counts.has(role)) role = 'all';
      const focused = roleFilter.contains(document.activeElement) ? document.activeElement.dataset.role : null;
      roleFilter.replaceChildren(
        filterButton('all', 'All', users.length),
        ...roles.filter((r) => counts.has(r.name)).reverse().map((r) => filterButton(r.name, r.label, counts.get(r.name))));
      if (focused) roleFilter.querySelector(`[data-role="${CSS.escape(focused)}"]`)?.focus();

      const term = search.value.trim().toLowerCase();
      const shown = users.filter((user) =>
        (role === 'all' || user.role === role) &&
        (!term || user.name.toLowerCase().includes(term) || user.email.toLowerCase().includes(term)));

      if (shown.length) {
        rows.replaceChildren(...shown.map(row));
        return;
      }
      const empty = term
        ? emptyState('No one matches that search', 'Check the spelling, or search by email instead.')
        : emptyState(role === 'all' ? 'No people yet' : `Nobody is ${roleNoun(role)}`, "Change someone's role from the All view, or add a person.");
      rows.replaceChildren(h('tr', {}, h('td', { colspan: 6 }, empty)));
    }

    function row(user) {
      const isMe = user.id === me.id;
      const locked = !isMe && !canManage(user);
      const select = h('select', {
        class: 'role-select',
        'aria-label': `Role for ${user.name}`,
        title: isMe ? "You can't change your own role" : locked ? 'Only the CEO can change this account' : null,
        disabled: isMe || locked,
      }, roleOptions(user.role, me.clearance));
      select.addEventListener('change', () => changeRole(user, select.value));

      return h('tr', {},
        h('td', {}, h('div', { class: 'person' },
          h('span', { class: isPrivileged(user.role) ? 'avatar is-admin' : 'avatar', 'aria-hidden': 'true' }, initials(user.name)),
          h('div', { class: 'person-text' },
            h('span', { class: 'person-name' }, user.name, isMe && h('span', { class: 'you' }, '(you)')),
            h('span', { class: 'person-email' }, user.email)))),
        h('td', {}, select),
        h('td', { class: 'num' }, String(user.project_count)),
        h('td', { class: 'date' }, formatDate(user.created_at)),
        h('td', { class: 'date' }, user.last_login_at ? formatDate(user.last_login_at) : 'Never'),
        h('td', {}, h('div', { class: 'row-actions' },
          // Your own password goes through the account dialog, which asks for your current password.
          !locked && h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => (isMe ? account.open() : openReset(user)) },
            isMe ? 'Change password' : 'Reset password'),
          // No delete on your own row: the server refuses it so an admin always remains.
          !isMe && !locked && h('button', { class: 'btn btn-quiet btn-danger btn-sm', type: 'button', 'aria-label': `Delete ${user.name}`, onclick: () => removeUser(user) }, 'Delete'),
          locked && h('span', { class: 'muted row-note' }, 'Managed by the CEO'))));
    }

    function openReset(user) {
      resetTarget = user;
      resetDialog.open({
        title: `Reset password for ${user.name}`,
        note: `${user.name} is signed out everywhere. After signing in with this password, they choose a new one.`,
      });
    }

    async function changeRole(user, nextRole) {
      try {
        const { user: saved } = await api('PATCH', `/api/admin/users/${user.id}/role`, { role: nextRole });
        Object.assign(user, { role: saved.role, clearance: saved.clearance });
        toast(`${user.name} is now ${roleNoun(nextRole)}`);
        onChange();
      } catch (err) {
        toast(err.message, 'error');
      }
      render(); // on failure this snaps the dropdown back to the saved role
    }

    async function removeUser(user) {
      const message = `Delete ${user.name} (${user.email})?\n\nTheir account and ${plural(user.project_count, 'project')} will be permanently removed.`;
      if (!confirm(message)) return;
      try {
        await api('DELETE', `/api/admin/users/${user.id}`);
        users = users.filter((u) => u.id !== user.id);
        render();
        toast(`Deleted ${user.name}`);
        onChange();
      } catch (err) {
        toast(err.message, 'error');
      }
    }

    return { load, render };
  }

  // ---- roles (the console reads them; only the CEO changes them) ---------------------------

  function mountRoles(me, onChange) {
    const rows = $('#role-rows');
    const note = $('#roles-note');
    const addButton = $('#add-role');
    const isCeo = me.role === 'ceo';
    let editing = null;

    const clearance = h('select', { id: uid('role-clearance'), name: 'clearance' },
      [1, 2, 3, 4, 5].map((level) => h('option', { value: level, selected: level === 2 }, `${level}, can be given ${CONFIDENTIALITY[level]} files`)));
    const dialog = formDialog({
      title: 'New role',
      submitLabel: 'Create role',
      fields: [
        field('Name', h('input', { id: uid('role-label'), name: 'label', maxlength: 40, autocomplete: 'off', required: true, placeholder: 'Contractors' })),
        field('Clearance', clearance, { hint: 'The most confidential file people in this role can be given. Employees are 2, admins 4 and the CEO 5.' }),
      ],
      async onSubmit(form) {
        const body = { label: form.elements.label.value, clearance: Number(clearance.value) };
        const { role } = editing
          ? await api('PATCH', `/api/admin/roles/${editing.id}`, body)
          : await api('POST', '/api/admin/roles', body);
        toast(editing ? `Saved the ${role.label} role` : `Created the ${role.label} role`);
        await load();
      },
    });

    addButton.hidden = !isCeo;
    addButton.addEventListener('click', () => {
      editing = null;
      dialog.open({
        title: 'New role',
        note: 'Everyone in a role can open files shared with it, up to its clearance. Roles you add never get the admin console.',
        submitLabel: 'Create role',
        values: { clearance: '2' },
      });
    });

    function openEdit(role) {
      editing = role;
      dialog.open({
        title: `Edit ${role.label}`,
        note: `Changing the clearance changes which shared files the ${people(role.member_count || 0)} in this role can open.`,
        submitLabel: 'Save role',
        values: { label: role.label, clearance: String(role.clearance) },
      });
    }

    async function remove(role) {
      if (!confirm(`Delete the ${role.label} role?\n\nFiles shared with it stop being shared through it.`)) return;
      try {
        await api('DELETE', `/api/admin/roles/${role.id}`);
        toast(`Deleted the ${role.label} role`);
        await load();
      } catch (err) {
        toast(err.message, 'error');
      }
    }

    async function load() {
      try {
        ({ roles } = await api('GET', '/api/roles'));
        render();
        onChange();
      } catch (err) {
        toast(err.message, 'error');
      }
    }

    function render() {
      const added = roles.filter((role) => !role.built_in).length;
      note.textContent = `${plural(roles.length, 'role')}${added ? `, ${added} added by the CEO` : ''}. `
        + (isCeo ? "Clearance is the most confidential file a role can be given. Built-in roles can't be changed." : 'Only the CEO can add or change roles.');
      rows.replaceChildren(...roles.slice().reverse().map((role) => h('tr', {},
        h('td', {}, h('div', { class: 'role-name' },
          h('span', { class: 'person-name' }, role.label),
          role.built_in && h('span', { class: 'tag' }, 'Built in'))),
        h('td', {}, levelMeter(role.clearance, { text: `${role.clearance}, up to ${CONFIDENTIALITY[role.clearance]}` })),
        h('td', { class: 'num' }, String(role.member_count ?? 0)),
        h('td', { class: 'muted' }, isPrivileged(role.name) ? 'Admin console and CrimGuard' : 'Their own projects, and files shared with them'),
        h('td', {}, h('div', { class: 'row-actions' },
          isCeo && !role.built_in && h('button', { class: 'btn btn-quiet btn-sm', type: 'button', 'aria-label': `Edit ${role.label}`, onclick: () => openEdit(role) }, 'Edit'),
          isCeo && !role.built_in && h('button', { class: 'btn btn-quiet btn-danger btn-sm', type: 'button', 'aria-label': `Delete ${role.label}`, onclick: () => remove(role) }, 'Delete'))))));
    }

    return { load };
  }

  // ---- activity log (admins only) --------------------------------------------------------

  // What each recorded action means to a reader, and how much attention it deserves:
  // alert (red) for failed or destructive events, warn for access changes, ok for sign-ins, idle for the rest.
  const ACTIVITY = {
    'account.signup': () => ['Created an account', 'idle'],
    'login.succeeded': (e) => [e.details.portal === 'admin' ? 'Signed in to the admin console' : 'Signed in', 'ok'],
    'login.failed': (e) => [e.details.blocked ? 'Failed sign-in, sign-in paused' : 'Failed sign-in', 'alert'],
    logout: () => ['Logged out', 'idle'],
    'password.changed': () => ['Changed their password', 'idle'],
    'password.change_failed': () => ['Entered a wrong current password', 'alert'],
    'profile.updated': () => ['Updated their profile', 'idle'],
    'admin.user_created': (e) => [`Added as ${roleNoun(e.details.role || 'intern')}`, 'warn'],
    'admin.role_changed': (e) => [`Role changed from ${roleLabel(e.details.from)} to ${roleLabel(e.details.to)}`, 'warn'],
    'admin.password_reset': () => ['Password reset by an admin', 'warn'],
    'admin.user_deleted': () => ['Account deleted', 'alert'],
    'admin.role_created': (e) => [`Created the ${e.details.label} role, clearance ${e.details.clearance}`, 'warn'],
    'admin.role_updated': (e) => [`Changed the ${e.details.to.label} role to clearance ${e.details.to.clearance}`, 'warn'],
    'admin.role_deleted': (e) => [`Deleted the ${e.details.label} role`, 'warn'],
    'file.access_changed': (e) => [`Access to one of their files changed, now ${CONFIDENTIALITY[e.details.confidentiality.to]}`, 'warn'],
    'file.downloaded': () => ['One of their files was downloaded', 'idle'],
    'crimguard.person_viewed': () => ['Record opened in CrimGuard', 'idle'],
    'security.honeytoken_tripped': () => ['Changed a decoy project and was signed out', 'alert'],
  };
  const describe = (event) => (ACTIVITY[event.action] ? ACTIVITY[event.action](event) : [event.action, 'idle']);
  const needsAttention = (event) => ['alert', 'warn'].includes(describe(event)[1]);

  function mountActivity() {
    const rows = $('#activity-rows');
    const filterBar = $('#activity-filter');
    const more = $('#activity-more');
    let events = [];
    let nextBefore = null;
    let kind = 'all';
    let loading = false;

    for (const button of filterBar.querySelectorAll('button')) {
      button.addEventListener('click', () => {
        kind = button.dataset.kind;
        render();
      });
    }
    more.addEventListener('click', () => fetchPage(nextBefore));

    async function fetchPage(before) {
      if (loading) return;
      loading = true;
      more.disabled = true;
      try {
        const data = await api('GET', `/api/admin/audit?limit=100${before ? `&before=${before}` : ''}`);
        events = before ? events.concat(data.events) : data.events;
        nextBefore = data.nextBefore;
        render();
      } catch (err) {
        toast(err.message, 'error');
      } finally {
        loading = false;
        more.disabled = false;
      }
    }

    function render() {
      const attention = events.filter(needsAttention);
      for (const button of filterBar.querySelectorAll('button')) {
        button.setAttribute('aria-pressed', String(button.dataset.kind === kind));
        const count = button.querySelector('.count');
        if (count) count.textContent = attention.length;
      }
      more.hidden = !nextBefore;

      const shown = kind === 'attention' ? attention : events;
      if (!shown.length) {
        const empty = kind === 'attention'
          ? emptyState('Nothing needs attention', 'Failed sign-ins, role changes, password resets and deleted accounts show up here.')
          : emptyState('No activity yet', 'Sign-ins and account changes appear here as they happen.');
        rows.replaceChildren(h('tr', {}, h('td', { colspan: 5 }, empty)));
        return;
      }
      rows.replaceChildren(...shown.map(row));
    }

    function doneBy(event) {
      if (!event.actor_email) return h('span', { class: 'muted' }, 'Not signed in');
      if (event.actor_email === event.target_email) return h('span', { class: 'muted' }, 'Themselves');
      return event.actor_email;
    }

    function row(event) {
      const [label, level] = describe(event);
      return h('tr', {},
        h('td', {}, h('span', { class: `status event status-${level}` }, label)),
        h('td', { class: 'wrap' }, event.target_email || h('span', { class: 'muted' }, event.action.startsWith('admin.role_') ? 'Roles' : 'Unknown account')),
        h('td', { class: 'wrap' }, doneBy(event)),
        h('td', { class: 'date' }, event.ip || ''),
        h('td', { class: 'date' }, h('time', { datetime: parseSqlDate(event.occurred_at).toISOString() }, formatDateTime(event.occurred_at))));
    }

    return { load: () => fetchPage(null) };
  }

  // Pages with sections (the admin console; a user's projects and shared files) keep each one in a panel
  // named by its tab, so #people or #shared opens that section.
  function initSections(onShow) {
    const links = [...document.querySelectorAll('[data-tab]')];
    const panels = [...document.querySelectorAll('[data-panel]')];
    const titles = Object.fromEntries(links.map((link) => [link.dataset.tab, link.textContent.trim()]));

    function show() {
      const requested = location.hash.slice(1);
      const name = Object.hasOwn(titles, requested) ? requested : links[0].dataset.tab;
      for (const link of links) {
        if (link.dataset.tab === name) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      }
      for (const panel of panels) panel.hidden = panel.dataset.panel !== name;
      document.title = `${titles[name]} · Red`;
      onShow(name);
    }

    window.addEventListener('hashchange', show);
    show();
  }

  // ---- page entry points -------------------------------------------------------------

  const pages = {
    login: () => initAuthForm($('#auth-form'), '/api/login', { portal: document.body.dataset.portal }),
    signup: () => initAuthForm($('#auth-form'), '/api/signup'),
    async dashboard() {
      const { me } = await initShell();
      mountProjects($('#projects'), me);
      const shared = mountShared($('#shared'), me);
      initSections((name) => {
        if (name === 'shared') shared.load();
      });
    },
    async admin() {
      const { me, account } = await initShell();
      mountProjects($('#projects'), me);
      const rolesSection = mountRoles(me, () => peopleSection.render());
      const peopleSection = mountPeople(me, account, () => rolesSection.load());
      const activitySection = mountActivity();
      initSections((name) => {
        if (name === 'people') {
          peopleSection.load();
          rolesSection.load();
        }
        if (name === 'activity') activitySection.load();
      });
    },
    // The risk console shares the signed-in shell; its own table lives in risk-console.js.
    async risk() {
      await initShell();
    },
    // So does CrimGuard, which crimguard.js draws once the shell is ready.
    async crimguard() {
      resolveShell(await initShell());
    },
  };

  // The building blocks crimguard.js draws the CrimGuard dashboard with.
  let resolveShell;
  window.RedUI = Object.freeze({
    h, api, toast, download, emptyState, levelMeter, sharingSummary, roleLabel, isPrivileged, describe, accessDialog,
    formatBytes, formatDate, formatDateTime, parseSqlDate, initials, plural, people,
    CONFIDENTIALITY, STATUS_LABELS,
    shell: new Promise((resolve) => { resolveShell = resolve; }),
  });

  initReveal();
  const init = pages[document.body.dataset.page];
  if (init) Promise.resolve(init()).catch((err) => toast(err.message, 'error'));
})();
