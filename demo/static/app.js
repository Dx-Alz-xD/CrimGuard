'use strict';

(() => {
  const STATUS_LABELS = { planning: 'Planning', active: 'Active', done: 'Done' };
  const ROLE_LABELS = { user: 'User', admin: 'Admin' };
  const AUTH_ENDPOINTS = ['/api/login', '/api/signup'];

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
  // English picks the article by sound ("a user", "an admin"), so spell it out for the role words used here.
  const withArticle = (word) => `${word === 'admin' ? 'an' : 'a'} ${word}`;
  const initials = (name) =>
    name.split(/\s+/).filter(Boolean).slice(0, 2).map((word) => [...word][0].toUpperCase()).join('') || '?';

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
  const roleOptions = (selected) =>
    Object.entries(ROLE_LABELS).map(([value, label]) => h('option', { value, selected: value === selected }, label));

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

  async function api(method, url, body) {
    const options = { method, headers: {} };
    if (method !== 'GET') {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body || {});
    }
    const res = await fetch(url, options);
    const data = res.status === 204 ? {} : await res.json().catch(() => ({}));
    if (res.ok) return data;

    if (res.status === 401 && !AUTH_ENDPOINTS.includes(url)) {
      go(document.body.dataset.page === 'admin' ? '/admin/login' : '/login');
    } else if (res.status === 403 && data.code === 'password_change_required') {
      location.reload(); // the page asks for a new password as it loads
    } else if (res.status === 403 && url.startsWith('/api/admin/')) {
      go('/dashboard'); // this account's admin role was removed while the page was open
    }
    const error = new Error(data.error || `Something went wrong (${res.status}). Try again.`);
    error.status = res.status;
    throw error;
  }

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
    return { me: user, account };
  }

  function emptyState(title, text, action) {
    return h('div', { class: 'empty' },
      h('h2', {}, title),
      h('p', {}, text),
      action && h('button', { class: 'btn btn-primary', type: 'button', onclick: action.run }, action.label));
  }

  // ---- projects (the user dashboard and an admin's own projects) ------------------

  function mountProjects(root) {
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
      dialog.open({ title: 'New project', note: 'Only you will be able to see it.', submitLabel: 'Create project' });
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
        surface.replaceChildren(emptyState('No projects yet', 'Create a project to start tracking it. Only you will see it.', { label: 'New project', run: openNew }));
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
          h('p', { class: 'project-name' }, project.name),
          project.description && h('p', { class: 'project-desc' }, project.description)),
        h('span', { class: 'project-updated' }, `Updated ${formatDate(project.updated_at)}`),
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

  function mountPeople(me, account) {
    const rows = $('#user-rows');
    const summary = $('#people-summary');
    const search = $('#user-search');
    const roleFilter = $('#role-filter');
    let users = [];
    let role = 'all';
    let resetTarget = null;

    const addDialog = formDialog({
      title: 'Add a person',
      note: 'Share this password with them directly. They choose their own the first time they sign in.',
      submitLabel: 'Add person',
      fields: [
        field('Full name', h('input', { id: uid('person-name'), name: 'name', maxlength: 80, autocomplete: 'off', required: true })),
        field('Email', h('input', { id: uid('person-email'), name: 'email', type: 'email', autocomplete: 'off', required: true })),
        h('div', { class: 'field-pair' },
          passwordField('Password', 'password', { hint: 'At least 12 characters.' }),
          field('Role', h('select', { id: uid('person-role'), name: 'role' }, roleOptions('user')))),
      ],
      async onSubmit(form) {
        const { user } = await api('POST', '/api/admin/users', Object.fromEntries(new FormData(form)));
        toast(`Added ${user.name} as ${withArticle(ROLE_LABELS[user.role].toLowerCase())}`);
        await load();
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

    $('#add-person').addEventListener('click', () => addDialog.open());
    search.addEventListener('input', render);
    for (const button of roleFilter.querySelectorAll('button')) {
      button.addEventListener('click', () => {
        role = button.dataset.role;
        render();
      });
    }

    async function load() {
      try {
        ({ users } = await api('GET', '/api/admin/users'));
        render();
      } catch (err) {
        toast(err.message, 'error');
      }
    }

    function render() {
      const admins = users.filter((user) => user.role === 'admin').length;
      summary.textContent = `${people(users.length)}, ${plural(admins, 'admin')}`;
      const counts = { all: users.length, admin: admins, user: users.length - admins };
      for (const button of roleFilter.querySelectorAll('button')) {
        button.setAttribute('aria-pressed', String(button.dataset.role === role));
        button.querySelector('.count').textContent = counts[button.dataset.role];
      }

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
        : emptyState(`No ${role === 'admin' ? 'admins' : 'users'} yet`, 'Change someone\'s role from the All view, or add a person.');
      rows.replaceChildren(h('tr', {}, h('td', { colspan: 6 }, empty)));
    }

    function row(user) {
      const isMe = user.id === me.id;
      const select = h('select', {
        class: 'role-select',
        'aria-label': `Role for ${user.name}`,
        title: isMe ? "You can't change your own role" : null,
        disabled: isMe,
      }, roleOptions(user.role));
      select.addEventListener('change', () => changeRole(user, select.value));

      return h('tr', {},
        h('td', {}, h('div', { class: 'person' },
          h('span', { class: user.role === 'admin' ? 'avatar is-admin' : 'avatar', 'aria-hidden': 'true' }, initials(user.name)),
          h('div', { class: 'person-text' },
            h('span', { class: 'person-name' }, user.name, isMe && h('span', { class: 'you' }, '(you)')),
            h('span', { class: 'person-email' }, user.email)))),
        h('td', {}, select),
        h('td', { class: 'num' }, String(user.project_count)),
        h('td', { class: 'date' }, formatDate(user.created_at)),
        h('td', { class: 'date' }, user.last_login_at ? formatDate(user.last_login_at) : 'Never'),
        h('td', {}, h('div', { class: 'row-actions' },
          // Your own password goes through the account dialog, which asks for your current password.
          h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => (isMe ? account.open() : openReset(user)) },
            isMe ? 'Change password' : 'Reset password'),
          // No delete on your own row: the server refuses it so an admin always remains.
          !isMe && h('button', { class: 'btn btn-quiet btn-danger btn-sm', type: 'button', 'aria-label': `Delete ${user.name}`, onclick: () => removeUser(user) }, 'Delete'))));
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
        await api('PATCH', `/api/admin/users/${user.id}/role`, { role: nextRole });
        user.role = nextRole;
        toast(`${user.name} is now ${withArticle(ROLE_LABELS[nextRole].toLowerCase())}`);
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
      } catch (err) {
        toast(err.message, 'error');
      }
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
    'admin.user_created': (e) => [`Added as ${withArticle(e.details.role || 'user')}`, 'warn'],
    'admin.role_changed': (e) => [`Role changed from ${ROLE_LABELS[e.details.from] || e.details.from} to ${ROLE_LABELS[e.details.to] || e.details.to}`, 'warn'],
    'admin.password_reset': () => ['Password reset by an admin', 'warn'],
    'admin.user_deleted': () => ['Account deleted', 'alert'],
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
        h('td', { class: 'wrap' }, event.target_email || h('span', { class: 'muted' }, 'Unknown account')),
        h('td', { class: 'wrap' }, doneBy(event)),
        h('td', { class: 'date' }, event.ip || ''),
        h('td', { class: 'date' }, h('time', { datetime: parseSqlDate(event.occurred_at).toISOString() }, formatDateTime(event.occurred_at))));
    }

    return { load: () => fetchPage(null) };
  }

  // Admin console sections live on one page: #projects, #people and #activity.
  function initSections(onShow) {
    const links = [...document.querySelectorAll('[data-tab]')];
    const panels = [...document.querySelectorAll('[data-panel]')];
    const titles = { projects: 'My projects', people: 'People & roles', activity: 'Activity' };

    function show() {
      const requested = location.hash.slice(1);
      const name = Object.hasOwn(titles, requested) ? requested : 'projects';
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
      await initShell();
      mountProjects($('#projects'));
    },
    async admin() {
      const { me, account } = await initShell();
      mountProjects($('#projects'));
      const peopleSection = mountPeople(me, account);
      const activitySection = mountActivity();
      initSections((name) => {
        if (name === 'people') peopleSection.load();
        if (name === 'activity') activitySection.load();
      });
    },
  };

  initReveal();
  const init = pages[document.body.dataset.page];
  if (init) Promise.resolve(init()).catch((err) => toast(err.message, 'error'));
})();
