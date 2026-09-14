'use strict';

// CrimGuard: everyone in Red and everything Red holds on them, kept live. For admins and the CEO;
// the server enforces that, and never names a file above the viewer's clearance.
//
// Drawn with app.js's building blocks (window.RedUI). While the tab is visible the roster refreshes
// every 15 seconds and the open record every 5. A record only redraws when something in it changed,
// so a button someone is about to press doesn't disappear from under them.

(() => {
  if (document.body.dataset.page !== 'crimguard' || !window.RedUI) return;

  const UI = window.RedUI;
  const { h, api, toast, formatBytes, formatDate, formatDateTime, parseSqlDate, initials, plural, levelMeter, isPrivileged } = UI;

  const ROSTER_MS = 15_000;
  const RECORD_MS = 5_000;
  const REDRAW_AT_LEAST_MS = 60_000; // so "5 min ago" keeps moving even when nothing else does
  const ONLINE_MS = 5 * 60_000;
  const LEVEL_CLASS = { low: 'status-ok', medium: 'status-warn', high: 'status-alert', critical: 'status-alert' };

  const byName = (a, b) => a.name.localeCompare(b.name);
  const lastLogin = (person) => (person.last_login_at ? parseSqlDate(person.last_login_at).getTime() : 0);
  const SORTS = {
    clearance: (a, b) => b.clearance - a.clearance || byName(a, b),
    active: (a, b) => (b.last_seen_at ?? 0) - (a.last_seen_at ?? 0) || lastLogin(b) - lastLogin(a) || byName(a, b),
    risk: (a, b) => (b.risk?.score ?? -1) - (a.risk?.score ?? -1) || byName(a, b),
    name: byName,
  };

  const $ = (selector) => document.querySelector(selector);
  const stats = $('#cg-stats');
  const roster = $('#cg-roster');
  const rosterCount = $('#cg-roster-count');
  const search = $('#cg-search');
  const roleFilter = $('#cg-filter');
  const sort = $('#cg-sort');
  const record = $('#cg-record');
  const live = $('#cg-live');
  const liveText = $('#cg-live-text');
  const narrow = window.matchMedia('(max-width: 900px)');

  let me = null;
  let overview = null;
  let selectedId = null;
  let detail = null;
  let signature = '';
  let drawnAt = 0;
  let seenEvents = null; // activity ids already on screen for this record, to mark new arrivals
  let updatedAt = 0;
  let failing = false;
  let roleKey = '';
  let access = null;

  // ---- small formatters ---------------------------------------------------------------

  function ago(ms) {
    const seconds = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (seconds < 45) return 'just now';
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 24) return `${plural(hours, 'hour')} ago`;
    return new Date(ms).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
  }

  // "Chrome on Windows" from a user agent string; enough to tell someone's devices apart.
  function device(userAgent = '') {
    const browser = /Edg\//.test(userAgent) ? 'Edge' : /OPR\//.test(userAgent) ? 'Opera' : /Firefox\//.test(userAgent) ? 'Firefox'
      : /Chrome\//.test(userAgent) ? 'Chrome' : /Safari\//.test(userAgent) ? 'Safari' : null;
    const system = /Windows/.test(userAgent) ? 'Windows' : /iPhone|iPad/.test(userAgent) ? 'iOS' : /Android/.test(userAgent) ? 'Android'
      : /Mac OS X/.test(userAgent) ? 'macOS' : /Linux/.test(userAgent) ? 'Linux' : null;
    if (browser && system) return `${browser} on ${system}`;
    return browser || system || userAgent.slice(0, 60) || 'Unknown browser';
  }

  function riskChip(risk) {
    if (!risk || risk.score == null) return h('span', { class: 'status status-idle cg-risk' }, 'Not scored');
    return h('span', { class: `status ${LEVEL_CLASS[risk.level] || 'status-idle'} cg-risk` }, `${Math.round(risk.score)} ${risk.level}`);
  }

  function presence(person) {
    if (person.online) return h('span', { class: 'cg-presence is-online' }, 'Online');
    return h('span', { class: 'cg-presence' }, person.last_login_at ? `Seen ${formatDate(person.last_login_at)}` : 'Never signed in');
  }

  // ---- the live indicator -----------------------------------------------------------------

  function tickLive() {
    if (!updatedAt) return;
    const seconds = Math.round((Date.now() - updatedAt) / 1000);
    const state = failing ? 'stale' : document.hidden ? 'paused' : 'live';
    live.dataset.state = state;
    liveText.textContent = state === 'stale' ? `Can't reach Red, retrying (last update ${seconds}s ago)`
      : state === 'paused' ? 'Paused while this tab is hidden'
        : `Live, updated ${seconds < 3 ? 'just now' : `${seconds}s ago`}`;
  }

  // Runs fn every `ms` while the tab is visible. now() runs it straight away, or as soon as the run in
  // progress finishes.
  function every(ms, fn) {
    let timer = setTimeout(run, ms);
    let running = false;
    let again = false;
    async function run() {
      clearTimeout(timer);
      if (running) {
        again = true;
        return;
      }
      running = true;
      if (!document.hidden) {
        try {
          await fn();
          failing = false;
          updatedAt = Date.now();
        } catch {
          failing = true;
        }
        tickLive();
      }
      running = false;
      if (again) {
        again = false;
        run();
        return;
      }
      timer = setTimeout(run, ms);
    }
    return { now: run };
  }

  // ---- summary and roster -----------------------------------------------------------------

  function renderStats() {
    const { totals, riskConnected } = overview;
    const stat = (label, value, note) =>
      h('div', { class: 'cg-stat' }, h('dt', {}, label), h('dd', {}, String(value), note && h('span', { class: 'cg-stat-note' }, note)));
    stats.replaceChildren(
      stat('People', totals.people),
      stat('Online now', totals.online),
      stat('Projects', totals.projects),
      stat('Files', totals.files, formatBytes(totals.bytes)),
      riskConnected ? stat('Open alerts', totals.alerts ?? 0) : stat('Risk scoring', 'Off', 'not connected'));
  }

  // Only rebuilt when the set of roles changes, so an open dropdown isn't snapped shut by a refresh.
  function renderRoleFilter() {
    const held = new Map(overview.people.map((person) => [person.role, person.role_label]));
    const key = [...held].join('|');
    if (key === roleKey) return;
    roleKey = key;
    const current = roleFilter.value;
    roleFilter.replaceChildren(
      h('option', { value: 'all' }, 'All roles'),
      ...[...held].map(([name, label]) => h('option', { value: name }, label)));
    roleFilter.value = held.has(current) ? current : 'all';
  }

  function renderRoster() {
    const term = search.value.trim().toLowerCase();
    const shown = overview.people
      .filter((person) => (roleFilter.value === 'all' || person.role === roleFilter.value)
        && (!term || person.name.toLowerCase().includes(term) || person.email.toLowerCase().includes(term)))
      .sort(SORTS[sort.value] || SORTS.clearance);

    rosterCount.textContent = shown.length === overview.people.length
      ? UI.people(shown.length)
      : `${shown.length} of ${UI.people(overview.people.length)}`;
    if (!shown.length) {
      roster.replaceChildren(h('li', { class: 'cg-roster-empty' }, 'No one matches. Check the spelling, or show all roles.'));
      return;
    }
    roster.replaceChildren(...shown.map((person) => h('li', {},
      h('a', { class: 'cg-person', href: `#person-${person.id}`, 'aria-current': person.id === selectedId ? 'true' : null },
        h('span', { class: isPrivileged(person.role) ? 'avatar is-admin' : 'avatar', 'aria-hidden': 'true' }, initials(person.name)),
        h('span', { class: 'cg-person-text' },
          h('span', { class: 'cg-person-name' }, person.name, person.id === me.id && h('span', { class: 'you' }, '(you)')),
          h('span', { class: 'cg-person-meta' }, `${person.role_label}, ${plural(person.project_count, 'project')}, ${plural(person.file_count, 'file')}`)),
        h('span', { class: 'cg-person-side' },
          overview.riskConnected && riskChip(person.risk),
          presence(person))))));
  }

  async function loadOverview() {
    overview = await api('GET', '/api/crimguard/overview');
    renderStats();
    renderRoleFilter();
    renderRoster();
  }

  // ---- one person's record ----------------------------------------------------------------

  const fact = (label, value) => h('div', { class: 'cg-fact' }, h('dt', {}, label), h('dd', {}, value));

  function section(title, body, { meta, note } = {}) {
    return h('section', { class: 'cg-section' },
      h('header', { class: 'cg-section-head' }, h('h3', {}, title), meta && h('span', { class: 'cg-section-meta' }, meta)),
      body,
      note && h('p', { class: 'cg-section-note' }, note));
  }

  function head({ person, sessions }) {
    const status = person.online ? 'Online now'
      : person.last_seen_at ? `Last active ${ago(person.last_seen_at)}` : 'Not signed in';
    const password = person.must_change_password ? 'Must choose a new one'
      : person.password_changed_at ? `Changed ${formatDate(person.password_changed_at)}` : 'Not set';
    const workplace = [person.job_title, person.organization].filter(Boolean).join(' at ');
    return h('header', { class: 'cg-record-head' },
      h('div', { class: 'cg-identity' },
        h('span', { class: isPrivileged(person.role) ? 'avatar avatar-lg is-admin' : 'avatar avatar-lg', 'aria-hidden': 'true' }, initials(person.name)),
        h('div', { class: 'cg-identity-text' },
          h('h2', { class: 'cg-name' }, person.name),
          h('p', { class: 'cg-subline' }, workplace ? `${person.email}, ${workplace}` : person.email))),
      h('dl', { class: 'cg-facts' },
        fact('Role', h('span', { class: 'cg-role' }, person.role_label, levelMeter(person.clearance, { text: `Clearance ${person.clearance}` }))),
        fact('Status', h('span', { class: person.online ? 'cg-presence is-online' : 'cg-presence' }, status)),
        fact('Signed in on', sessions.length ? plural(sessions.length, 'device') : 'No devices'),
        fact('Last sign-in', person.last_login_at ? formatDateTime(person.last_login_at) : 'Never'),
        fact('Joined', formatDate(person.created_at)),
        fact('Password', password)),
      person.bio && h('p', { class: 'cg-bio' }, person.bio));
  }

  function sparkline(history) {
    const points = history.filter((day) => day.score != null);
    if (points.length < 2) return null;
    const ns = 'http://www.w3.org/2000/svg';
    const make = (tag, attrs) => {
      const node = document.createElementNS(ns, tag);
      for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
      return node;
    };
    const width = 320;
    const height = 64;
    const top = Math.max(100, ...points.map((point) => point.score));
    const x = (i) => 4 + (i / (points.length - 1)) * (width - 8);
    const y = (score) => height - 4 - (score / top) * (height - 8);
    const line = points.map((point, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(point.score).toFixed(1)}`).join(' ');
    const last = points.at(-1);
    const svg = make('svg', {
      viewBox: `0 0 ${width} ${height}`, class: 'cg-spark', role: 'img',
      'aria-label': `Score over ${points.length} days, from ${Math.round(points[0].score)} to ${Math.round(last.score)}`,
    });
    svg.append(
      make('path', { class: 'cg-spark-area', d: `${line} L${x(points.length - 1).toFixed(1)} ${height - 4} L${x(0).toFixed(1)} ${height - 4} Z` }),
      make('path', { class: 'cg-spark-line', d: line }),
      make('circle', { class: 'cg-spark-dot', cx: x(points.length - 1).toFixed(1), cy: y(last.score).toFixed(1), r: 3.5 }));
    return svg;
  }

  function riskSection(risk) {
    if (!risk || risk.score == null) {
      return section('Risk', h('p', { class: 'muted' }, 'No score yet. One appears once this person has used Red and the day has been scored.'));
    }
    const context = [risk.scenario && risk.scenario.replace(/_/g, ' '), risk.date && `scored for ${risk.date}`].filter(Boolean).join(', ');
    return section('Risk',
      h('div', { class: 'cg-risk-body' },
        h('div', { class: 'cg-score' },
          h('span', { class: 'cg-score-value' }, risk.score.toFixed(1)),
          h('span', { class: `status ${LEVEL_CLASS[risk.level] || 'status-idle'}` }, risk.level),
          context && h('span', { class: 'cg-score-meta' }, context)),
        sparkline(risk.history),
        risk.contributions.length
          ? h('ol', { class: 'cg-drivers', 'aria-label': 'What is raising the score' }, risk.contributions.map((item) =>
            h('li', {}, h('span', {}, String(item.feature).replace(/_/g, ' ')), h('span', { class: 'risk-points' }, `+${item.points}`))))
          : h('p', { class: 'muted cg-drivers-none' }, 'Nothing is raising this score.')),
      { meta: 'From the risk engine. The risk console has all 100 variables.' });
  }

  function openAccess(file) {
    access = access || UI.accessDialog(me);
    access.open(file, () => loadRecord({ force: true }).catch((err) => toast(err.message, 'error')));
  }

  // A list rather than a table: the record pane can be narrow, and names need room to wrap whole.
  function fileRow(file) {
    return h('li', { class: 'cg-file' },
      h('div', { class: 'cg-file-main' },
        h('p', { class: 'cg-file-name' }, file.name),
        h('p', { class: 'cg-file-meta' },
          levelMeter(file.confidentiality),
          h('span', {}, UI.sharingSummary(file)),
          h('span', {}, formatBytes(file.size)),
          h('span', {}, `Updated ${formatDate(file.updated_at)}`))),
      h('div', { class: 'row-actions cg-file-actions' },
        // An admin can open a Secret file the CEO shared with them by name, but not change who else can.
        file.confidentiality <= me.clearance && h('button', {
          class: 'btn btn-quiet btn-sm', type: 'button', 'data-focus': `access-${file.id}`,
          'aria-label': `Choose who can see ${file.name}`, onclick: () => openAccess(file),
        }, 'Access'),
        h('button', {
          class: 'btn btn-quiet btn-sm', type: 'button', 'data-focus': `download-${file.id}`, 'aria-label': `Download ${file.name}`,
          onclick: () => UI.download(`/api/files/${file.id}/download`, file.name).catch((err) => toast(err.message, 'error')),
        }, 'Download')));
  }

  function projectBlock(project) {
    return h('article', { class: 'cg-project' },
      h('header', { class: 'cg-project-head' },
        h('h4', {}, project.name),
        h('span', { class: `status status-${project.status}` }, UI.STATUS_LABELS[project.status]),
        h('span', { class: 'cg-project-meta' }, `Updated ${formatDate(project.updated_at)}`)),
      project.description && h('p', { class: 'cg-project-desc' }, project.description),
      project.files.length > 0 && h('ul', { class: 'cg-file-list' }, project.files.map(fileRow)),
      project.hidden_files > 0 && h('p', { class: 'cg-hidden-note' }, `${plural(project.hidden_files, 'file')} above your clearance, not listed`),
      !project.files.length && !project.hidden_files && h('p', { class: 'cg-project-empty' }, 'No files.'));
  }

  function projectsSection({ person, projects, totals }) {
    const meta = `${plural(projects.length, 'project')}, ${plural(totals.files, 'file')}, ${formatBytes(totals.bytes)}`;
    const body = projects.length
      ? h('div', { class: 'cg-projects' }, projects.map(projectBlock))
      : h('p', { class: 'muted' }, `${person.name} has no projects yet.`);
    return section('Projects and files', body, { meta });
  }

  function sharedSection({ shared }) {
    const body = shared.length
      ? h('ul', { class: 'cg-list' }, shared.map((file) => h('li', { class: 'cg-list-row' },
        h('span', { class: 'cg-file-name', title: file.name }, file.name),
        levelMeter(file.confidentiality),
        h('span', { class: 'muted' }, `From ${file.owner_name}'s ${file.project_name}, ${file.by_name ? 'by name' : 'through their role'}`))))
      : h('p', { class: 'muted' }, 'Nothing from other people has been shared with them.');
    return section('Shared with them', body, { meta: plural(shared.length, 'file') });
  }

  function sessionsSection({ sessions }) {
    const body = sessions.length
      ? h('ul', { class: 'cg-list' }, sessions.map((session) => h('li', { class: 'cg-list-row' },
        h('span', { class: 'cg-device' }, device(session.user_agent)),
        h('span', { class: 'muted' }, `Signed in ${ago(session.created_at)}`),
        h('span', { class: Date.now() - session.last_seen_at < ONLINE_MS ? 'cg-presence is-online' : 'cg-presence' }, `Active ${ago(session.last_seen_at)}`))))
      : h('p', { class: 'muted' }, 'Not signed in anywhere.');
    return section('Signed in now', body, { meta: plural(sessions.length, 'session') });
  }

  function activitySection({ person, activity }, firstDraw) {
    const body = activity.length
      ? h('ol', { class: 'cg-timeline' }, activity.map((event) => {
        const [label, level] = UI.describe(event);
        const at = parseSqlDate(event.occurred_at);
        const who = [
          !event.actor_email ? 'not signed in' : event.actor_email !== person.email && `by ${event.actor_email}`,
          event.target_email && event.target_email !== person.email && `about ${event.target_email}`,
          event.ip,
        ].filter(Boolean).join(', ');
        const isNew = !firstDraw && !seenEvents.has(event.id);
        return h('li', { class: isNew ? 'cg-event is-new' : 'cg-event' },
          h('span', { class: `status event status-${level}` }, label),
          h('time', { class: 'cg-event-time', datetime: at.toISOString(), title: formatDateTime(event.occurred_at) }, ago(at.getTime())),
          who && h('span', { class: 'cg-event-meta' }, who));
      }))
      : h('p', { class: 'muted' }, 'No activity recorded.');
    return section('Activity', body, { meta: 'Newest first' });
  }

  function draw() {
    const firstDraw = seenEvents === null;
    // Keep keyboard focus on the same control across a redraw.
    const focusKey = document.activeElement?.closest?.('[data-focus]')?.dataset.focus;
    record.replaceChildren(
      head(detail),
      detail.riskConnected && riskSection(detail.risk),
      projectsSection(detail),
      sharedSection(detail),
      sessionsSection(detail),
      activitySection(detail, firstDraw));
    seenEvents = new Set(detail.activity.map((event) => event.id));
    drawnAt = Date.now();
    if (focusKey) record.querySelector(`[data-focus="${CSS.escape(focusKey)}"]`)?.focus();
  }

  async function loadRecord({ force = false } = {}) {
    const id = selectedId;
    if (id == null) return;
    let data;
    try {
      data = await api('GET', `/api/crimguard/people/${id}`);
    } catch (err) {
      if (err.status !== 404) throw err;
      if (id === selectedId) {
        detail = null;
        record.replaceChildren(UI.emptyState('That account no longer exists', 'It may have been deleted. Choose someone else from the list.'));
      }
      return;
    }
    if (id !== selectedId) return;
    const next = JSON.stringify({ ...data, generatedAt: null });
    if (!force && next === signature && Date.now() - drawnAt < REDRAW_AT_LEAST_MS) return;
    signature = next;
    detail = data;
    draw();
  }

  // ---- selection, from the address bar so a record can be linked to and reloaded ----------

  let recordLoop = null;

  function selectFromHash() {
    const match = /^#person-(\d+)$/.exec(location.hash);
    const id = match ? Number(match[1]) : null;
    if (id === selectedId) return;
    selectedId = id;
    detail = null;
    signature = '';
    seenEvents = null;
    record.replaceChildren(id == null
      ? UI.emptyState('Choose someone', 'Their projects, files, devices and activity open here and stay up to date.')
      : h('div', { class: 'empty' }, h('p', {}, 'Opening record…')));
    if (overview) renderRoster();
    if (id != null) {
      recordLoop.now();
      if (narrow.matches) record.scrollIntoView({ block: 'start' });
    }
  }

  // With nothing chosen yet, open someone other than yourself with the most to look at, preferring
  // people who are online.
  function firstPerson() {
    const others = overview.people.filter((person) => person.id !== me.id);
    const weight = (person) => (person.online ? 1e6 : 0) + person.file_count * 10 + person.project_count;
    return others.sort((a, b) => weight(b) - weight(a))[0] || overview.people[0];
  }

  UI.shell.then(async (shell) => {
    me = shell.me;
    search.addEventListener('input', renderRoster);
    roleFilter.addEventListener('change', renderRoster);
    sort.addEventListener('change', renderRoster);

    try {
      await loadOverview();
      updatedAt = Date.now();
    } catch (err) {
      record.replaceChildren(UI.emptyState("CrimGuard couldn't load", err.message));
      return;
    }

    const rosterLoop = every(ROSTER_MS, loadOverview);
    recordLoop = every(RECORD_MS, loadRecord);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        rosterLoop.now();
        recordLoop.now();
      }
      tickLive();
    });
    setInterval(tickLive, 1000);

    if (!location.hash && overview.people.length) history.replaceState(null, '', `#person-${firstPerson().id}`);
    window.addEventListener('hashchange', selectFromHash);
    selectFromHash();
    tickLive();
  });
})();
