'use strict';

// The live risk panel: a button in the bottom-left corner that opens a movable window showing
// the signed-in person their own risk score and all 100 variables behind it.
//
// Everyone can see this about themselves. The endpoint it reads takes the account from the
// session, so there is no way to point it at anyone else. It is deliberately the same numbers
// an admin would see in the risk console - if the app is going to score people, the person
// being scored should be able to read the score.

(() => {
  const ENDPOINT = '/api/me/risk';
  // While the panel is open the whole loop is tightened: the collector closes a window every
  // 15 seconds instead of every minute, and the score is refetched just after each one, so
  // what you do shows up in the score within seconds rather than a minute or two.
  const POLL_MS = 6000;
  const LIVE_WINDOW_MS = 15_000;
  const TICK_MS = 250;
  const STORAGE = 'red:risk-panel';
  const MARGIN = 12;

  const page = document.body.dataset.page;
  if (page !== 'dashboard' && page !== 'admin' && page !== 'risk') return;

  const CATEGORY_LABELS = {
    access_resource: 'Access & resources',
    temporal: 'Timing',
    data_movement: 'Data movement',
    authentication_identity: 'Authentication & identity',
    device_network: 'Device & network',
    behavioral_biometrics: 'Behavioural biometrics',
    hr_org_context: 'HR & organisation',
    communication_collaboration: 'Communication',
    privilege_permission: 'Privilege & permission',
    physical_environmental: 'Physical & environmental',
  };
  const COLLECTION_LABELS = { measured: 'measured', derived: 'derived', 'no-source': 'no source' };
  const LEVEL_CLASS = { low: 'status-ok', medium: 'status-warn', high: 'status-alert', critical: 'status-alert' };

  // Same builder idea as app.js: children are appended as nodes or text, so nothing from the
  // server is ever parsed as HTML.
  function h(tag, props = {}, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (value == null || value === false) continue;
      if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
      else if (key === 'class') el.className = value;
      else el.setAttribute(key, value === true ? '' : value);
    }
    el.append(...children.flat().filter((child) => child != null && child !== false));
    return el;
  }

  const load = (fallback) => {
    try { return { ...fallback, ...JSON.parse(localStorage.getItem(STORAGE) || '{}') }; } catch { return fallback; }
  };
  const save = (state) => {
    try { localStorage.setItem(STORAGE, JSON.stringify(state)); } catch { /* private window: position just won't stick */ }
  };

  const state = load({ open: false, x: null, y: null, onlyFilled: false });

  // ---- formatting -------------------------------------------------------------------

  function formatValue(value, valueType) {
    if (value === null || value === undefined) return null;
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (typeof value === 'number') {
      if (Number.isInteger(value)) return String(value);
      if (Math.abs(value) >= 100) return value.toFixed(0);
      if (Math.abs(value) >= 1) return value.toFixed(2);
      return value.toFixed(3);
    }
    if (valueType === 'category') return String(value).replace(/_/g, ' ');
    return String(value);
  }

  // "usually 41", or for a flag how often it has been true. Empty when there is no history
  // to compare against yet.
  function formatUsual(feature) {
    if (feature.usual === null || feature.usual === undefined || !feature.baselineDays) return null;
    if (feature.valueType === 'flag') {
      const percent = Math.round(feature.usual * 100);
      return percent === 0 ? 'never before' : percent === 100 ? 'always' : `${percent}% of days`;
    }
    if (typeof feature.usual !== 'number') return null;
    return `usually ${formatValue(feature.usual, feature.valueType)}`;
  }

  // ---- the panel --------------------------------------------------------------------

  const scoreValue = h('span', { class: 'risk-score-value' }, '—');
  const scoreLevel = h('span', { class: 'status risk-score-level' }, 'No score yet');
  const scoreMeta = h('p', { class: 'risk-score-meta' }, 'Loading your assessment…');
  const scoredAge = h('span', { class: 'risk-scored-age' }, '');
  const coverageLine = h('p', { class: 'risk-coverage' });
  const list = h('div', { class: 'risk-list' });

  const onlyFilled = h('input', {
    type: 'checkbox', id: 'risk-only-filled', checked: state.onlyFilled || null,
    onchange: () => {
      state.onlyFilled = onlyFilled.checked;
      save(state);
      if (latest) render(latest);
    },
  });

  // What the collector has accumulated in the window it has not sent yet. This is read
  // straight out of the page several times a second, so it moves as you type and point.
  // Kept to one compact band: the variables below are what the panel is actually for.
  const liveRows = [
    ['keystrokes', 'keys', (l) => (l.keystrokes ? `${l.keystrokes}${l.keyIntervalMean ? ` @ ${l.keyIntervalMean}ms` : ''}` : '0')],
    ['pointer', 'pointer', (l) => (l.mouseVelocityNow ? `${l.mouseVelocityNow} px/s` : l.pointerSamples ? 'still' : '0')],
    ['scroll', 'scroll', (l) => String(l.scrollEvents || 0)],
    ['copyPaste', 'copy', (l) => String(l.copyPaste || 0)],
    ['switches', 'focus', (l) => String(l.appSwitches || 0)],
    ['idle', 'idle', (l) => `${l.idleSeconds || 0}s`],
    ['tabs', 'tabs', (l) => String(l.tabs || 1)],
  ];
  const liveValues = new Map(liveRows.map(([key]) => [key, h('span', { class: 'risk-chip-value' }, '—')]));
  const liveCountdown = h('span', { class: 'risk-live-next' }, '');
  const liveStats = h('div', { class: 'risk-chips' }, liveRows.map(([key, label]) =>
    h('span', { class: 'risk-chip' }, h('span', { class: 'risk-chip-label' }, label), liveValues.get(key))));

  const sendNow = h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => sendAndRefresh() }, 'Send now');
  const liveSection = h('div', { class: 'risk-live' },
    h('div', { class: 'risk-live-head' },
      h('span', { class: 'risk-pulse', 'aria-hidden': 'true' }),
      h('span', { class: 'risk-live-title' }, 'Being captured now'),
      liveCountdown,
      sendNow),
    liveStats);

  const refreshButton = h('button', { class: 'btn btn-quiet btn-sm', type: 'button', onclick: () => refresh({ force: true }) }, 'Refresh');
  const closeButton = h('button', {
    class: 'risk-close', type: 'button', 'aria-label': 'Close the risk panel', onclick: () => toggle(false),
  }, '×');

  const title = h('span', { class: 'risk-title' }, 'Your risk assessment');
  const header = h('div', { class: 'risk-header' }, h('span', { class: 'risk-grip', 'aria-hidden': 'true' }), title, closeButton);

  const panel = h('section', {
    class: 'risk-panel', id: 'risk-panel', hidden: true,
    role: 'dialog', 'aria-label': 'Your live risk assessment',
  },
  header,
  h('div', { class: 'risk-score' },
    h('div', { class: 'risk-score-main' }, scoreValue, scoreLevel, scoredAge),
    scoreMeta),
  h('div', { class: 'risk-controls' },
    h('label', { class: 'risk-toggle', for: 'risk-only-filled' }, onlyFilled, 'Only variables with a value'),
    refreshButton),
  liveSection,
  h('div', { class: 'risk-scroll' }, list),
  coverageLine);

  const launcher = h('button', {
    class: 'risk-launcher', type: 'button', 'aria-expanded': 'false', 'aria-controls': 'risk-panel',
    title: 'Your live risk assessment', onclick: () => toggle(!state.open),
  }, h('span', { class: 'risk-launcher-dot', 'aria-hidden': 'true' }), h('span', {}, 'Risk'), h('span', { class: 'risk-launcher-score' }, ''));

  document.body.append(launcher, panel);

  // ---- moving it around ----------------------------------------------------------------

  // Keeps the panel on screen, including after the window is resized smaller.
  function place(x, y) {
    const width = panel.offsetWidth || 340;
    const height = panel.offsetHeight || 420;
    const maxX = Math.max(MARGIN, innerWidth - width - MARGIN);
    const maxY = Math.max(MARGIN, innerHeight - height - MARGIN);
    state.x = Math.min(Math.max(x, MARGIN), maxX);
    state.y = Math.min(Math.max(y, MARGIN), maxY);
    panel.style.left = `${state.x}px`;
    panel.style.top = `${state.y}px`;
  }

  function placeDefault() {
    const height = panel.offsetHeight || 420;
    place(MARGIN, Math.max(MARGIN, innerHeight - height - 64));
  }

  let dragging = null;
  header.addEventListener('pointerdown', (event) => {
    if (event.target === closeButton || event.button !== 0) return;
    dragging = { dx: event.clientX - panel.offsetLeft, dy: event.clientY - panel.offsetTop };
    header.setPointerCapture(event.pointerId);
    panel.classList.add('is-dragging');
  });
  header.addEventListener('pointermove', (event) => {
    if (!dragging) return;
    event.preventDefault();
    place(event.clientX - dragging.dx, event.clientY - dragging.dy);
  });
  const endDrag = (event) => {
    if (!dragging) return;
    dragging = null;
    panel.classList.remove('is-dragging');
    header.releasePointerCapture?.(event.pointerId);
    save(state);
  };
  header.addEventListener('pointerup', endDrag);
  header.addEventListener('pointercancel', endDrag);

  // The header is a drag handle, so give it a keyboard equivalent.
  header.tabIndex = 0;
  header.addEventListener('keydown', (event) => {
    const step = event.shiftKey ? 40 : 10;
    const moves = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
    const move = moves[event.key];
    if (!move) return;
    event.preventDefault();
    place(panel.offsetLeft + move[0], panel.offsetTop + move[1]);
    save(state);
  });

  addEventListener('resize', () => { if (state.open) place(panel.offsetLeft, panel.offsetTop); });
  addEventListener('keydown', (event) => { if (event.key === 'Escape' && state.open) toggle(false); });

  // ---- rendering -----------------------------------------------------------------------

  let latest = null;

  let lastScore = null;
  let scoredAt = null;

  function render(data) {
    latest = data;
    const score = data.score;

    if (score) {
      const now = Number(score.finalScore);
      // A brief flash when the number actually changes, so a rescore is visible rather than
      // something you have to catch by watching.
      if (lastScore !== null && Math.abs(now - lastScore) >= 0.05) {
        scoreValue.dataset.direction = now > lastScore ? 'up' : 'down';
        scoreValue.classList.remove('is-changed');
        void scoreValue.offsetWidth; // restart the animation
        scoreValue.classList.add('is-changed');
      }
      lastScore = now;
      scoreValue.textContent = now.toFixed(1);
      scoreLevel.textContent = score.riskLevel;
      scoreLevel.className = `status risk-score-level ${LEVEL_CLASS[score.riskLevel] || 'status-idle'}`;
      launcher.dataset.level = score.riskLevel;
      launcher.querySelector('.risk-launcher-score').textContent = Number(score.finalScore).toFixed(0);

      const quality = score.dataQuality;
      const scenario = score.scenario ? score.scenario.replace(/_/g, ' ') : 'nothing unusual';
      scoreMeta.textContent = quality
        ? `${scenario} · ${quality.featuresScored} variables scored · ${quality.medianBaselineDays} days of baseline`
        : scenario;
      scoredAt = data.scoredAt ? Date.parse(data.scoredAt) : null;
    } else {
      scoreValue.textContent = '—';
      scoreLevel.textContent = data.date ? 'Not scored yet' : 'No activity today';
      scoreLevel.className = 'status risk-score-level status-idle';
      scoreMeta.textContent = data.date
        ? `Collected for ${data.date}. A score appears once there is enough history.`
        : 'Use Red for a moment and this fills in.';
      launcher.removeAttribute('data-level');
      launcher.querySelector('.risk-launcher-score').textContent = '';
      scoredAt = null;
    }

    const points = new Map((score?.contributions || []).map((item) => [item.feature, item.points]));
    const groups = new Map();
    for (const feature of data.features) {
      if (!groups.has(feature.category)) groups.set(feature.category, []);
      groups.get(feature.category).push(feature);
    }

    const sections = [];
    let shown = 0;
    for (const [category, features] of groups) {
      const filled = features.filter((feature) => feature.value !== null);
      const visible = state.onlyFilled ? filled : features;
      if (!visible.length) continue;
      shown += visible.length;

      sections.push(h('div', { class: 'risk-group' },
        h('div', { class: 'risk-group-head' },
          h('h3', {}, CATEGORY_LABELS[category] || category),
          h('span', { class: 'count' }, `${filled.length}/${features.length}`)),
        h('ul', { class: 'risk-rows' }, visible.map((feature) => {
          const value = formatValue(feature.value, feature.valueType);
          const contribution = points.get(feature.key);
          const usual = formatUsual(feature);
          return h('li', {
            class: `risk-row${value === null ? ' is-empty' : ''}${contribution ? ' is-flagged' : ''}`,
            title: usual ? `${feature.note}
Usually ${usual} over the last ${feature.baselineDays} days.` : feature.note,
          },
          h('span', { class: 'risk-key' }, feature.key.replace(/_/g, ' ')),
          h('span', { class: 'risk-value' }, value === null ? '—' : value),
          usual ? h('span', { class: 'risk-usual', title: 'what is usual for you' }, usual) : null,
          contribution
            ? h('span', { class: 'risk-points', title: `${contribution} of the score comes from this` }, `+${contribution}`)
            : h('span', { class: `risk-tag risk-tag-${feature.collection}` }, COLLECTION_LABELS[feature.collection]));
        }))));
    }

    list.replaceChildren(...(sections.length ? sections : [h('p', { class: 'risk-none' }, 'Nothing collected yet today.')]));

    const c = data.coverage || {};
    coverageLine.textContent = `${shown} shown · Red collects ${c.collected ?? 0} of ${c.total ?? 0} variables; `
      + `${c['no-source'] ?? 0} need a system Red isn't connected to.`;

    // The panel is placed while it is still empty and grows as the rows arrive, so pull it
    // back inside the viewport once it has its real height.
    place(panel.offsetLeft, panel.offsetTop);
  }

  // ---- the live readout ---------------------------------------------------------------------

  let liveTimer = null;

  function tickLive() {
    const collector = window.RED_TELEMETRY;
    if (!collector) {
      liveCountdown.textContent = 'collector not running';
      return;
    }
    const l = collector.live();
    for (const [key, , format] of liveRows) liveValues.get(key).textContent = format(l);

    if (scoredAt) {
      const age = Math.max(0, Math.round((Date.now() - scoredAt) / 1000));
      scoredAge.textContent = age < 60 ? `rescored ${age}s ago` : `rescored ${Math.round(age / 60)}m ago`;
    } else {
      scoredAge.textContent = '';
    }

    const seconds = Math.ceil(l.nextSendInMs / 1000);
    liveCountdown.textContent = l.queued ? `${l.queued} queued · ${seconds}s` : `${seconds}s`;
    liveCountdown.title = l.queued
      ? `${l.queued} window(s) waiting to be sent. The next one closes in ${seconds} seconds.`
      : `The current window closes and is sent in ${seconds} seconds.`;
  }

  // Close the current window, push it, and refetch the score once the server has had it.
  async function sendAndRefresh() {
    sendNow.disabled = true;
    try {
      window.RED_TELEMETRY?.flush();
      await new Promise((resolve) => setTimeout(resolve, 400));
      await refresh({ force: true });
    } finally {
      sendNow.disabled = false;
    }
  }

  // ---- loading ---------------------------------------------------------------------------

  let inFlight = false;
  let timer = null;

  async function refresh({ force = false } = {}) {
    if (inFlight || (!state.open && !force)) return;
    inFlight = true;
    refreshButton.disabled = true;
    try {
      const res = await fetch(ENDPOINT, { headers: { Accept: 'application/json' } });
      if (res.status === 401) return toggle(false);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        scoreMeta.textContent = body.error || `Could not load the assessment (${res.status}).`;
        return;
      }
      render(await res.json());
    } catch {
      scoreMeta.textContent = 'Could not reach the server. Trying again shortly.';
    } finally {
      inFlight = false;
      refreshButton.disabled = false;
    }
  }

  function toggle(open) {
    state.open = open;
    save(state);
    panel.hidden = !open;
    launcher.setAttribute('aria-expanded', String(open));
    clearInterval(timer);
    clearInterval(liveTimer);

    if (!open) {
      // Back to a window a minute long once nobody is watching.
      window.RED_TELEMETRY?.setWindow(60_000);
      return;
    }

    if (state.x === null || state.y === null) placeDefault();
    else place(state.x, state.y);

    window.RED_TELEMETRY?.setWindow(LIVE_WINDOW_MS);
    tickLive();
    liveTimer = setInterval(tickLive, TICK_MS);
    refresh({ force: true });
    timer = setInterval(refresh, POLL_MS);
  }

  if (state.open) toggle(true);
})();
