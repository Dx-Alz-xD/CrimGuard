'use strict';

// Red's behavioural collector. Feeds the variables in the CrimGuard feature catalog that the
// server cannot see for itself: pointer and typing rhythm, scrolling, idle time, focus
// changes, clipboard size, printing, screen capture, and the browser's own description of
// itself.
//
// What leaves this page, and what does not:
//
//   sent      timing statistics (means and standard deviations over a one-minute window),
//             counts of events, the number of characters copied, and the *names* of any
//             secret-shaped patterns matched ("api_key"), plus a device fingerprint.
//   not sent  which keys were pressed, where the pointer went, what was selected, and the
//             text of anything copied or pasted. Classification happens here, in the page,
//             and only the category names survive it.
//
// Everything else - which projects were opened, what was searched for, who signed in, who
// changed a role - is recorded by the server, where it cannot be forged from here.

(() => {
  const ENDPOINT = '/api/telemetry';
  const WINDOW_MS = 60_000; // one biometric sample per minute
  const TICK_MS = 2000;
  const IDLE_AFTER_MS = 30_000;
  const HEARTBEAT_MS = 5000;
  const TAB_TIMEOUT_MS = 12_000;
  const MAX_EVENTS = 180;
  const LARGE_COPY = 5000;

  // Only signed-in pages collect anything; the login and sign-up pages have no session.
  const page = document.body.dataset.page;
  if (page !== 'dashboard' && page !== 'admin' && page !== 'risk') return;
  // The admin console shows other people's account records, so anything captured there is
  // capturing confidential material.
  const sensitiveScreen = page === 'admin' || page === 'risk';

  // ---- what a window accumulates --------------------------------------------------

  const empty = () => ({
    start: Date.now(),
    keyIntervals: [],
    keyDwells: [],
    mouseVelocities: [],
    scrollEvents: 0,
    scrollVelocities: [],
    appSwitches: 0,
    idleMs: 0,
    copyPaste: 0,
  });

  let sample = empty();
  const pending = [];
  const events = [];

  const add = (event) => {
    if (events.length < MAX_EVENTS) events.push({ ...event, at: new Date().toISOString() });
  };

  const mean = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
  const stdev = (xs) => {
    if (xs.length < 2) return null;
    const m = mean(xs);
    return Math.sqrt(xs.reduce((total, x) => total + (x - m) ** 2, 0) / (xs.length - 1));
  };
  const round = (value, places = 2) => (value === null ? null : Number(value.toFixed(places)));

  // ---- typing rhythm (timing only, never the keys) --------------------------------

  let lastKeyDown = 0;
  const downAt = new Map();

  addEventListener('keydown', (event) => {
    touch();
    const now = performance.now();
    if (lastKeyDown && now - lastKeyDown < 5000) sample.keyIntervals.push(now - lastKeyDown);
    lastKeyDown = now;
    // event.code is used only to notice Print Screen, and is never recorded.
    if (event.code === 'PrintScreen') add({ type: 'screenshot' });
    if (!downAt.has(event.code)) downAt.set(event.code, now);
  }, { passive: true, capture: true });

  addEventListener('keyup', (event) => {
    const started = downAt.get(event.code);
    if (started !== undefined) {
      sample.keyDwells.push(performance.now() - started);
      downAt.delete(event.code);
    }
  }, { passive: true, capture: true });

  // ---- pointer and scrolling -------------------------------------------------------

  let lastMove = null;
  let currentVelocity = 0;
  addEventListener('mousemove', (event) => {
    touch();
    const now = performance.now();
    if (lastMove) {
      const seconds = (now - lastMove.t) / 1000;
      if (seconds > 0.01 && seconds < 1) {
        const distance = Math.hypot(event.clientX - lastMove.x, event.clientY - lastMove.y);
        if (distance > 0) {
          sample.mouseVelocities.push(distance / seconds);
          // Smoothed, for the live readout only. Never sent: positions stay in this page.
          currentVelocity = currentVelocity * 0.7 + (distance / seconds) * 0.3;
        }
      }
    }
    lastMove = { x: event.clientX, y: event.clientY, t: now };
  }, { passive: true });

  let lastScroll = null;
  addEventListener('scroll', () => {
    touch();
    sample.scrollEvents += 1;
    const now = performance.now();
    const y = scrollY;
    if (lastScroll) {
      const seconds = (now - lastScroll.t) / 1000;
      if (seconds > 0.01 && seconds < 1) sample.scrollVelocities.push(Math.abs(y - lastScroll.y) / seconds);
    }
    lastScroll = { y, t: now };
  }, { passive: true, capture: true });

  // ---- focus, idle time and how many Red tabs are open -----------------------------

  let lastInput = Date.now();
  const touch = () => { lastInput = Date.now(); };
  for (const type of ['pointerdown', 'touchstart', 'wheel']) addEventListener(type, touch, { passive: true });

  addEventListener('visibilitychange', () => {
    sample.appSwitches += 1;
    add({ type: 'app_switch' });
  });
  addEventListener('blur', () => { sample.appSwitches += 1; });

  const tabId = Math.random().toString(36).slice(2);
  const tabsSeen = new Map([[tabId, Date.now()]]);
  let channel = null;
  try {
    channel = new BroadcastChannel('red-telemetry');
    channel.addEventListener('message', (event) => {
      if (event.data && typeof event.data.tab === 'string') tabsSeen.set(event.data.tab, Date.now());
    });
    setInterval(() => {
      tabsSeen.set(tabId, Date.now());
      channel.postMessage({ tab: tabId });
    }, HEARTBEAT_MS);
  } catch { /* no BroadcastChannel: the count stays at this tab */ }

  const openTabs = () => {
    const cutoff = Date.now() - TAB_TIMEOUT_MS;
    for (const [id, seen] of tabsSeen) if (seen < cutoff) tabsSeen.delete(id);
    return tabsSeen.size;
  };

  // ---- clipboard: length and shape, never content ----------------------------------

  // The same categories the server knows about. Matching happens here so the text itself
  // never leaves the page.
  const SECRETS = [
    ['private_key', /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/],
    ['api_key', /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/],
    ['api_key', /\bAKIA[0-9A-Z]{16}\b/],
    ['api_key', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
    ['token', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
    ['password', /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*\S{6,}/i],
    ['credit_card', /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{2,4}\b/],
    ['ssn', /\b\d{3}-\d{2}-\d{4}\b/],
    ['source_code', /\b(?:function|const|class|import|SELECT .* FROM|def )\b[\s\S]{40,}/],
  ];

  function classify(text) {
    const found = new Set();
    for (const [name, pattern] of SECRETS) if (pattern.test(text)) found.add(name);
    if ((text.match(/[^\s@]+@[^\s@]+\.[^\s@]+/g) || []).length >= 5) found.add('email_list');
    return [...found];
  }

  function clipboardEvent(type, text) {
    sample.copyPaste += 1;
    const value = typeof text === 'string' ? text : '';
    add({ type, chars: value.length, patterns: value.length >= 24 ? classify(value) : [] });
  }

  for (const type of ['copy', 'cut']) {
    addEventListener(type, () => clipboardEvent(type, String(getSelection() || '')), { capture: true });
  }
  addEventListener('paste', (event) => {
    let text = '';
    try { text = event.clipboardData?.getData('text') || ''; } catch { /* blocked: the count still counts */ }
    clipboardEvent('paste', text);
  }, { capture: true });

  // ---- printing and screen capture --------------------------------------------------

  addEventListener('beforeprint', () => {
    add({ type: 'print', pages: Math.max(1, Math.ceil(document.body.scrollHeight / 1100)), sensitive: sensitiveScreen });
  });

  // Screen sharing and recording started from this page.
  if (navigator.mediaDevices?.getDisplayMedia) {
    const original = navigator.mediaDevices.getDisplayMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getDisplayMedia = (...args) => {
      add({ type: 'screen_recording', sensitive: sensitiveScreen });
      return original(...args);
    };
  }

  // ---- who this browser is ------------------------------------------------------------

  // A stable, coarse fingerprint. Enough to notice a new device, not enough to be an identifier
  // on its own: no canvas, fonts, audio or any of the other high-entropy tricks.
  function fingerprint() {
    const parts = [
      navigator.userAgent, navigator.platform || '', navigator.language || '',
      `${screen.width}x${screen.height}x${screen.colorDepth}`,
      String(navigator.hardwareConcurrency || 0),
      Intl.DateTimeFormat().resolvedOptions().timeZone || '',
    ].join('|');
    // FNV-1a: short, stable and dependency-free. The server hashes it again before storing.
    let hash = 0x811c9dc5;
    for (let i = 0; i < parts.length; i++) {
      hash ^= parts.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return `${hash.toString(16)}-${parts.length.toString(16)}`;
  }

  const device = () => ({
    fingerprint: fingerprint(),
    platform: navigator.platform || null,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
    screen: `${screen.width}x${screen.height}`,
    language: navigator.language || null,
    cores: navigator.hardwareConcurrency || null,
  });

  // ---- windows and sending ------------------------------------------------------------

  function closeWindow() {
    const seconds = Math.round((Date.now() - sample.start) / 1000);
    if (seconds < 1) return;
    const typed = sample.keyIntervals.length > 0;
    const moved = sample.mouseVelocities.length > 0;

    pending.push({
      at: new Date(sample.start).toISOString(),
      seconds,
      keyIntervalMean: typed ? round(mean(sample.keyIntervals)) : null,
      keyIntervalStd: typed ? round(stdev(sample.keyIntervals)) : null,
      keyDwellMean: sample.keyDwells.length ? round(mean(sample.keyDwells)) : null,
      mouseVelocityMean: moved ? round(mean(sample.mouseVelocities)) : null,
      mouseVelocityStd: moved ? round(stdev(sample.mouseVelocities)) : null,
      scrollEvents: sample.scrollEvents,
      scrollVelocityMean: sample.scrollVelocities.length ? round(mean(sample.scrollVelocities)) : null,
      appSwitches: sample.appSwitches,
      idleSeconds: Math.min(seconds, Math.round(sample.idleMs / 1000)),
      windows: openTabs(),
      copyPaste: sample.copyPaste,
    });
    sample = empty();
  }

  let sending = false;
  let lastSentAt = null;
  function send({ beacon = false } = {}) {
    if (sending || (!pending.length && !events.length)) return;
    lastSentAt = Date.now();
    const body = JSON.stringify({
      device: device(),
      windows: openTabs(),
      samples: pending.splice(0, pending.length),
      events: events.splice(0, events.length),
    });

    // On the way out the page may not live long enough for fetch to finish.
    if (beacon && navigator.sendBeacon) {
      navigator.sendBeacon(ENDPOINT, new Blob([body], { type: 'application/json' }));
      return;
    }
    sending = true;
    fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      keepalive: true,
    }).catch(() => { /* offline or signed out: the next window tries again */ })
      .finally(() => { sending = false; });
  }

  setInterval(() => {
    if (Date.now() - lastInput >= IDLE_AFTER_MS) sample.idleMs += TICK_MS;
    // The pointer stopping should read as zero, not as the last speed it was going.
    if (Date.now() - lastInput > 400) currentVelocity *= 0.5;
  }, TICK_MS);

  let windowMs = WINDOW_MS;
  let windowTimer = null;
  function restartWindowTimer() {
    clearInterval(windowTimer);
    windowTimer = setInterval(() => {
      closeWindow();
      send();
    }, windowMs);
  }
  restartWindowTimer();

  // What the current, unsent window holds. Read by the risk panel several times a second so
  // the capture is visible as it happens; none of this goes anywhere on its own.
  function live() {
    const now = Date.now();
    const idleFor = now - lastInput;
    return {
      windowMs: now - sample.start,
      windowLength: windowMs,
      nextSendInMs: Math.max(0, windowMs - (now - sample.start)),
      lastSentAt,
      keystrokes: sample.keyIntervals.length,
      keyIntervalMean: sample.keyIntervals.length ? Math.round(mean(sample.keyIntervals)) : null,
      keyDwellMean: sample.keyDwells.length ? Math.round(mean(sample.keyDwells)) : null,
      pointerSamples: sample.mouseVelocities.length,
      mouseVelocityMean: sample.mouseVelocities.length ? Math.round(mean(sample.mouseVelocities)) : null,
      mouseVelocityNow: Math.round(currentVelocity),
      scrollEvents: sample.scrollEvents,
      appSwitches: sample.appSwitches,
      copyPaste: sample.copyPaste,
      idleSeconds: Math.round(sample.idleMs / 1000),
      idleNow: idleFor >= IDLE_AFTER_MS,
      tabs: openTabs(),
      queued: pending.length + events.length,
    };
  }

  // The panel exposes a "send now" so you don't have to wait out the window to see the score move.
  window.RED_TELEMETRY = {
    live,
    flush() {
      closeWindow();
      send();
      restartWindowTimer();
    },
    // While the panel is open the window is shortened, so values reach the server in seconds
    // rather than a minute. window_seconds is stored per sample, so the aggregation is unaffected.
    setWindow(ms) {
      windowMs = Math.min(Math.max(Number(ms) || WINDOW_MS, 5000), WINDOW_MS);
      restartWindowTimer();
    },
  };

  addEventListener('pagehide', () => {
    closeWindow();
    send({ beacon: true });
  });
  addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      closeWindow();
      send({ beacon: true });
    }
  });
})();
