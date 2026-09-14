'use strict';

// The live console at the foot of the CrimGuard dashboard: security events as Red writes them.
//
// It looks like a terminal because that is the fastest way to read a stream, but it only reads.
// Every command below runs here, in the page, and changes what is shown - nothing typed into it
// is sent anywhere. The server side is one read-only endpoint (src/routes/events.js).

(() => {
  const root = document.getElementById('cg-console');
  if (!root || !window.RedUI) return;

  const { h, api, describe } = window.RedUI;

  const POLL_MS = 3000;
  const MAX_LINES = 500;
  const LEVELS = ['alert', 'warn', 'ok', 'info'];

  const output = root.querySelector('#cg-console-output');
  const form = root.querySelector('#cg-console-form');
  const input = root.querySelector('#cg-console-input');
  const state = root.querySelector('#cg-console-state');

  const events = []; // everything received, newest last, capped at MAX_LINES
  let cursor = null;
  let paused = false;
  let filter = '';
  let minimum = 'info';
  let failing = false;
  const history = [];
  let historyAt = 0;

  // How much attention an action deserves. The activity log's own wording is used for the text
  // where it has one; the level is decided from the action's name, so new kinds of event land in
  // the right colour before anyone writes a sentence for them.
  function levelOf(action) {
    if (/failed|locked|tripped|blocked|deleted|shadow_ai|freeze|frozen/.test(action)) return 'alert';
    if (/^(admin|risk|security|file\.access)[._]/.test(action)) return 'warn';
    if (/succeeded|passed|signup|restored/.test(action)) return 'ok';
    return 'info';
  }

  const SUMMARY_KEYS = ['portal', 'destination', 'channel', 'chars', 'document', 'decision', 'role', 'from', 'to',
    'attempts', 'score', 'decoy', 'interaction', 'confidentiality', 'daysLeft', 'blocked'];

  // A few of the event's details, as key=value. Only flat values: nested ones are left to the
  // activity log, which has room for them.
  function detailsOf(details = {}) {
    return SUMMARY_KEYS
      .filter((key) => details[key] !== undefined && details[key] !== null && typeof details[key] !== 'object')
      .map((key) => `${key}=${String(details[key]).slice(0, 60)}`)
      .join(' ');
  }

  const timeOf = (value) => {
    const date = new Date(`${String(value).replace(' ', 'T')}Z`);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleTimeString([], { hour12: false });
  };

  function visible(event) {
    if (LEVELS.indexOf(levelOf(event.action)) > LEVELS.indexOf(minimum)) return false;
    if (!filter) return true;
    const haystack = [event.action, event.actor_email, event.target_email, event.ip, JSON.stringify(event.details)]
      .join(' ').toLowerCase();
    return haystack.includes(filter);
  }

  function eventLine(event) {
    const level = levelOf(event.action);
    let text = '';
    try { [text] = describe(event); } catch { /* an event older than the wording for it */ }
    const who = event.actor_email || event.target_email || 'someone';
    const target = event.target_email && event.target_email !== event.actor_email ? ` → ${event.target_email}` : '';
    return h('li', { class: `cg-console-line is-${level}`, 'data-id': event.id },
      h('time', { class: 'cg-console-time', datetime: event.occurred_at }, timeOf(event.occurred_at)),
      h('span', { class: 'cg-console-level' }, level.toUpperCase()),
      h('span', { class: 'cg-console-action' }, event.action),
      h('span', { class: 'cg-console-text' }, `${who}${target}${text && text !== event.action ? ` · ${text}` : ''}`),
      h('span', { class: 'cg-console-details' }, detailsOf(event.details)));
  }

  const note = (text, kind = 'note') => h('li', { class: `cg-console-line is-${kind}` }, h('span', { class: 'cg-console-text' }, text));

  const atBottom = () => output.scrollHeight - output.scrollTop - output.clientHeight < 24;

  function append(nodes) {
    const stick = atBottom();
    output.append(...nodes);
    while (output.children.length > MAX_LINES) output.firstElementChild.remove();
    if (stick) output.scrollTop = output.scrollHeight;
  }

  function redraw() {
    output.replaceChildren(...events.filter(visible).map(eventLine));
    output.scrollTop = output.scrollHeight;
  }

  function showState() {
    const parts = [paused ? 'paused' : failing ? 'reconnecting' : 'live'];
    if (minimum !== 'info') parts.push(`level ≥ ${minimum}`);
    if (filter) parts.push(`filter “${filter}”`);
    state.textContent = parts.join(' · ');
    state.dataset.state = paused ? 'paused' : failing ? 'stale' : 'live';
  }

  // ---- commands, all local ----------------------------------------------------------------

  const COMMANDS = {
    help: () => [
      'Read-only: these commands change what this view shows. Nothing typed here is sent to the server.',
      '  filter <text>   show events mentioning text (an email, an action, an address)',
      '  filter          show everything again',
      '  level <alert|warn|ok|info>   hide anything less important',
      '  pause / resume  stop and restart the stream',
      '  clear           empty the screen (new events still arrive)',
      '  last <n>        show only the latest n events',
      '  count           how many events are held, by level',
    ].forEach((line) => append([note(line)])),
    filter: (args) => { filter = args.join(' ').toLowerCase(); redraw(); },
    level: ([value]) => {
      if (!LEVELS.includes(value)) return append([note(`level must be one of: ${LEVELS.join(', ')}`, 'error')]);
      minimum = value;
      redraw();
      return undefined;
    },
    pause: () => { paused = true; },
    resume: () => { paused = false; poll(); },
    clear: () => output.replaceChildren(),
    last: ([value]) => {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 1) return append([note('last needs a number, e.g. last 20', 'error')]);
      output.replaceChildren(...events.filter(visible).slice(-n).map(eventLine));
      return undefined;
    },
    count: () => {
      const counts = Object.fromEntries(LEVELS.map((level) => [level, 0]));
      for (const event of events) counts[levelOf(event.action)] += 1;
      append([note(`${events.length} events held: ${LEVELS.map((level) => `${counts[level]} ${level}`).join(', ')}`)]);
    },
  };

  function run(line) {
    const [name, ...args] = line.trim().split(/\s+/);
    if (!name) return;
    append([h('li', { class: 'cg-console-line is-echo' }, h('span', { class: 'cg-console-text' }, `> ${line.trim()}`))]);
    const key = name.toLowerCase();
    const command = Object.hasOwn(COMMANDS, key) ? COMMANDS[key] : null;
    if (!command) {
      append([note(`Unknown command "${name}". This console only reads events - type help.`, 'error')]);
    } else {
      command(args);
    }
    showState();
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const line = input.value;
    input.value = '';
    if (line.trim()) {
      history.push(line);
      historyAt = history.length;
    }
    run(line);
  });

  input.addEventListener('keydown', (event) => {
    if (event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return;
    event.preventDefault();
    historyAt = Math.max(0, Math.min(history.length, historyAt + (event.key === 'ArrowUp' ? -1 : 1)));
    input.value = history[historyAt] ?? '';
  });

  // ---- the stream ---------------------------------------------------------------------------

  let timer = null;
  let polling = false;

  async function poll() {
    clearTimeout(timer);
    if (polling) return;
    polling = true;
    let more = false;
    try {
      if (!paused && !document.hidden) {
        const reply = await api('GET', `/api/admin/events${cursor === null ? '' : `?after=${cursor}`}`);
        failing = false;
        cursor = reply.cursor;
        more = reply.more;
        if (reply.events.length) {
          events.push(...reply.events);
          events.splice(0, Math.max(0, events.length - MAX_LINES));
          append(reply.events.filter(visible).map(eventLine));
        }
      }
    } catch {
      failing = true;
    } finally {
      polling = false;
      showState();
      timer = setTimeout(poll, more ? 0 : POLL_MS);
    }
  }

  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  append([note('Live security events. Read-only - type help for what this view can do.')]);
  showState();
  poll();
})();
