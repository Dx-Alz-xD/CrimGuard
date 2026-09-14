'use strict';

// CrimGuard behavioural biometrics: learns how the account owner types and moves the pointer, so
// a different person at the keyboard - a borrowed laptop, a hijacked session - shows up even
// though the password was right.
//
// This is the page's only keyboard and pointer listener for risk purposes. telemetry.js takes its
// coarse typing and pointer averages from here (subscribe below) rather than listening again, so
// what is captured, and what is skipped, is defined once.
//
// What leaves this page, and what does not:
//
//   sent      one vector per window: medians and spreads of hold and between-key times grouped
//             by which hand moved, and of pointer stroke speed, acceleration, straightness,
//             click hold and pause (see src/biometrics/features.js), plus a coarse device
//             fingerprint.
//   not sent  which keys were pressed, anything typed, or where the pointer was. Each key is
//             reduced to a zone the moment it goes down and each movement to stroke statistics;
//             positions and key identities are dropped immediately. Password fields are ignored.

(() => {
  const ENDPOINT = '/api/biometrics/windows';
  const MIN_KEYS = 40;
  const MIN_STROKES = 15;
  const PAUSE_MS = 1500;
  const MAX_GAP_MS = 10_000;
  const MAX_HOLD_MS = 2000;
  const STROKE_GAP_MS = 150;
  const MIN_STROKE_PX = 20;
  const FULL_WINDOW_KEYS = 400;
  const FULL_WINDOW_STROKES = 80;
  const WINDOW_MS = 60_000;
  const IDLE_SEND_MS = 15_000;
  const STALE_WINDOW_MS = 5 * 60_000;
  const TICK_MS = 5000;

  // ---- keys to zones (event.code is the physical position, whatever the layout) ----------

  const LEFT = new Set(['KeyQ', 'KeyW', 'KeyE', 'KeyR', 'KeyT', 'KeyA', 'KeyS', 'KeyD', 'KeyF', 'KeyG',
    'KeyZ', 'KeyX', 'KeyC', 'KeyV', 'KeyB', 'Backquote']);
  const RIGHT = new Set(['KeyY', 'KeyU', 'KeyI', 'KeyO', 'KeyP', 'KeyH', 'KeyJ', 'KeyK', 'KeyL', 'KeyN', 'KeyM',
    'Semicolon', 'Quote', 'Comma', 'Period', 'Slash', 'BracketLeft', 'BracketRight', 'Minus', 'Equal']);
  const MODIFIERS = new Set(['ControlLeft', 'ControlRight', 'AltLeft', 'AltRight', 'MetaLeft', 'MetaRight', 'CapsLock']);

  function zoneOf(code) {
    if (LEFT.has(code)) return 'L';
    if (RIGHT.has(code)) return 'R';
    if (code === 'Space') return 'S';
    if (code === 'Backspace' || code === 'Delete') return 'B';
    if (code === 'ShiftLeft') return 'LS';
    if (code === 'ShiftRight') return 'RS';
    if (MODIFIERS.has(code)) return 'M';
    if (/^(Digit|Numpad)\d$/.test(code)) return 'D';
    return 'O';
  }

  const isLetter = (zone) => zone === 'L' || zone === 'R';
  const isTyping = (zone) => zone === 'L' || zone === 'R' || zone === 'S';
  const isModifier = (zone) => zone === 'LS' || zone === 'RS' || zone === 'M';

  function transition(from, to) {
    if (isLetter(from) && isLetter(to)) return from + to;
    if (isLetter(from) && to === 'S') return 'XS';
    if (from === 'S' && isLetter(to)) return 'SX';
    return null;
  }

  // ---- statistics ---------------------------------------------------------------------------

  const sorted = (xs) => [...xs].sort((a, b) => a - b);
  function quantile(xs, q) {
    const s = sorted(xs);
    const pos = (s.length - 1) * q;
    const lo = Math.floor(pos);
    const hi = Math.ceil(pos);
    return s[lo] + (s[hi] - s[lo]) * (pos - lo);
  }
  const median = (xs, min = 5) => (xs.length >= min ? quantile(xs, 0.5) : null);
  const iqr = (xs, min = 8) => (xs.length >= min ? quantile(xs, 0.75) - quantile(xs, 0.25) : null);
  const mean = (xs, min = 2) => (xs.length >= min ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
  const ratio = (hits, base, min) => (base >= min ? hits / base : null);
  const round = (value, places) => (value === null ? null : Number(value.toFixed(places)));

  // ---- the aggregator: timings in, one feature vector out ----------------------------------
  //
  // Pure: it is given (code, time) and (x, y, time) and never touches the page, which is also how
  // the server's tests drive it. A key's code is used to find its zone and to pair its up with its
  // down while held; a stroke's positions are used to measure it and dropped when it ends.

  function createAggregator({ emit = () => {} } = {}) {
    let s;

    function reset() {
      s = {
        keys: 0, firstAt: null, lastAt: null,
        dwell: { L: [], R: [], S: [] }, letterDwell: [],
        flight: { LL: [], LR: [], RL: [], RR: [], XS: [], SX: [] }, letterFlight: [],
        rolloverHits: 0, rolloverBase: 0, intervals: 0, pauses: 0, bursts: [], burst: 0, activeMs: 0,
        corrections: 0, shifts: { L: 0, R: 0 }, shiftLead: [], pendingShiftAt: null,
        held: new Map(), previous: null,
        strokes: [], stroke: null, lastMoveAt: null, clickDownAt: null, clickHold: [], clickPause: [],
      };
    }
    reset();

    const seen = (t) => {
      if (s.firstAt === null) s.firstAt = t;
      s.lastAt = t;
    };

    // --- keyboard ---

    function keyDown(code, t) {
      if (s.held.has(code)) return; // auto-repeat
      const zone = zoneOf(code);
      s.held.set(code, { zone, t });

      if (zone === 'LS' || zone === 'RS') {
        s.shifts[zone[0]] += 1;
        s.pendingShiftAt = t;
      }
      if (isModifier(zone)) return;

      seen(t);
      s.keys += 1;
      if (zone === 'B') s.corrections += 1;

      const previous = s.previous;
      if (previous) {
        const gap = t - previous.t;
        if (gap < MAX_GAP_MS) {
          s.intervals += 1;
          emit({ type: 'keyInterval', ms: gap });
          if (gap >= PAUSE_MS) {
            s.pauses += 1;
            if (s.burst) s.bursts.push(s.burst);
            s.burst = 0;
          } else {
            s.activeMs += gap;
            const pair = transition(previous.zone, zone);
            if (pair) s.flight[pair].push(gap);
            if (isLetter(previous.zone) && isLetter(zone)) s.letterFlight.push(gap);
          }
        } else if (s.burst) {
          s.bursts.push(s.burst);
          s.burst = 0;
        }
      }
      s.burst += 1;

      if (isTyping(zone)) {
        s.rolloverBase += 1;
        for (const [otherCode, other] of s.held) {
          if (otherCode !== code && isTyping(other.zone)) {
            s.rolloverHits += 1;
            break;
          }
        }
      }
      if (isLetter(zone) && s.pendingShiftAt !== null) {
        const lead = t - s.pendingShiftAt;
        if (lead < PAUSE_MS) s.shiftLead.push(lead);
        s.pendingShiftAt = null;
      }
      s.previous = { zone, t };
    }

    function keyUp(code, t) {
      const held = s.held.get(code);
      if (!held) return;
      s.held.delete(code);
      const hold = t - held.t;
      if (hold <= 0 || hold > MAX_HOLD_MS) return;
      if (!isModifier(held.zone)) emit({ type: 'keyDwell', ms: hold });
      if (!isTyping(held.zone)) return;
      s.dwell[held.zone].push(hold);
      if (isLetter(held.zone)) s.letterDwell.push(hold);
    }

    // --- pointer ---

    function endStroke() {
      const stroke = s.stroke;
      s.stroke = null;
      if (!stroke || stroke.points < 4 || stroke.path < MIN_STROKE_PX) return;
      const duration = stroke.lastT - stroke.startT;
      if (duration <= 0) return;
      const displacement = Math.hypot(stroke.lastX - stroke.startX, stroke.lastY - stroke.startY);
      const accel = stroke.accel.length ? stroke.accel.reduce((a, b) => a + b, 0) / stroke.accel.length : null;
      s.strokes.push({
        speed: stroke.path / (duration / 1000),
        peak: stroke.peak,
        straightness: Math.min(1, displacement / stroke.path),
        durationMs: duration,
        accel,
      });
    }

    function pointerMove(x, y, t) {
      const stroke = s.stroke;
      if (stroke && t - stroke.lastT > STROKE_GAP_MS) endStroke();
      if (!s.stroke) {
        s.stroke = { startX: x, startY: y, startT: t, lastX: x, lastY: y, lastT: t, path: 0, points: 1, peak: 0, speeds: [], accel: [], lastSpeed: null };
        s.lastMoveAt = t;
        return;
      }
      const st = s.stroke;
      const dt = t - st.lastT;
      if (dt <= 0) return;
      const distance = Math.hypot(x - st.lastX, y - st.lastY);
      if (distance === 0) return;
      const speed = distance / (dt / 1000);
      emit({ type: 'pointerVelocity', pxPerSecond: speed });
      // Peak over three samples, so one coalesced event doesn't set it.
      st.speeds.push(speed);
      if (st.speeds.length > 3) st.speeds.shift();
      if (st.speeds.length === 3) st.peak = Math.max(st.peak, st.speeds.reduce((a, b) => a + b, 0) / 3);
      if (st.lastSpeed !== null) st.accel.push(Math.abs(speed - st.lastSpeed) / (dt / 1000));
      st.lastSpeed = speed;
      st.path += distance;
      st.points += 1;
      Object.assign(st, { lastX: x, lastY: y, lastT: t });
      s.lastMoveAt = t;
      seen(t);
    }

    function pointerDown(t) {
      if (s.stroke) endStroke();
      if (s.lastMoveAt !== null && t - s.lastMoveAt < 2000) s.clickPause.push(t - s.lastMoveAt);
      s.clickDownAt = t;
      seen(t);
    }

    function pointerUp(t) {
      if (s.clickDownAt === null) return;
      const hold = t - s.clickDownAt;
      s.clickDownAt = null;
      if (hold > 0 && hold < MAX_HOLD_MS) s.clickHold.push(hold);
    }

    // Keys held when focus leaves the page never send their keyup.
    const releaseAll = () => {
      s.held.clear();
      s.clickDownAt = null;
      endStroke();
    };

    // The window as a feature vector, or null when there isn't enough of either to say anything.
    function summary() {
      if (s.stroke && s.lastAt !== null && s.lastAt - s.stroke.lastT >= 0) endStroke();
      const typed = s.keys >= MIN_KEYS;
      const moved = s.strokes.length >= MIN_STROKES;
      if (!typed && !moved) return null;

      const bursts = s.burst ? [...s.bursts, s.burst] : s.bursts;
      const shifts = s.shifts.L + s.shifts.R;
      const k = (value) => (typed ? value : null);
      const p = (value) => (moved ? value : null);
      const strokesOf = (field) => s.strokes.map((stroke) => stroke[field]).filter((v) => v !== null);

      return {
        keys: s.keys,
        strokes: s.strokes.length,
        seconds: Math.max(1, Math.round((s.lastAt - s.firstAt) / 1000)),
        features: {
          dwellL: k(round(median(s.dwell.L), 1)),
          dwellR: k(round(median(s.dwell.R), 1)),
          dwellSpace: k(round(median(s.dwell.S), 1)),
          dwellIqr: k(round(iqr(s.letterDwell), 1)),
          flightLL: k(round(median(s.flight.LL), 1)),
          flightLR: k(round(median(s.flight.LR), 1)),
          flightRL: k(round(median(s.flight.RL), 1)),
          flightRR: k(round(median(s.flight.RR), 1)),
          flightToSpace: k(round(median(s.flight.XS), 1)),
          flightFromSpace: k(round(median(s.flight.SX), 1)),
          flightIqr: k(round(iqr(s.letterFlight), 1)),
          rollover: k(round(ratio(s.rolloverHits, s.rolloverBase, 20), 3)),
          pauseRate: k(round(ratio(s.pauses, s.intervals, 20), 3)),
          burstLength: k(round(mean(bursts), 1)),
          correctionRate: k(round((100 * s.corrections) / Math.max(1, s.keys), 2)),
          rightShiftShare: k(round(ratio(s.shifts.R, shifts, 3), 3)),
          shiftLead: k(round(median(s.shiftLead, 3), 1)),
          keysPerMinute: k(s.activeMs >= 5000 ? round(s.keys / (s.activeMs / 60_000), 1) : null),

          pointerSpeed: p(round(median(strokesOf('speed')), 0)),
          pointerSpeedIqr: p(round(iqr(strokesOf('speed')), 0)),
          pointerPeakSpeed: p(round(median(strokesOf('peak')), 0)),
          pointerAccel: p(round(median(strokesOf('accel')), 0)),
          pointerStraightness: p(round(median(strokesOf('straightness')), 3)),
          pointerStrokeMs: p(round(median(strokesOf('durationMs')), 0)),
          clickHold: p(round(median(s.clickHold, 3), 1)),
          clickPause: p(round(median(s.clickPause, 3), 0)),
        },
      };
    }

    return {
      keyDown, keyUp, pointerMove, pointerDown, pointerUp, releaseAll, summary, reset,
      get keys() { return s.keys; },
      get strokes() { return s.strokes.length; },
      get lastAt() { return s.lastAt; },
    };
  }

  // Signals for other scripts on the page (telemetry.js): timings only, never keys or positions.
  const subscribers = [];
  const emit = (signal) => {
    for (const fn of subscribers) {
      try { fn(signal); } catch { /* one subscriber must not break collection */ }
    }
  };

  window.CrimGuardBiometrics = {
    createAggregator,
    subscribe(fn) { if (typeof fn === 'function') subscribers.push(fn); },
  };

  // ---- the collector (signed-in pages only) ---------------------------------------------------

  const page = document.body && document.body.dataset ? document.body.dataset.page : null;
  if (page !== 'dashboard' && page !== 'admin' && page !== 'risk') return;

  const aggregator = createAggregator({ emit });
  let windowStartedAt = null;
  let sending = false;
  const start = () => { if (windowStartedAt === null) windowStartedAt = Date.now(); };

  const ignoredKey = (event) => {
    if (event.isComposing || event.repeat) return true;
    const target = event.target;
    if (target && target.tagName === 'INPUT' && String(target.type).toLowerCase() === 'password') return true;
    return Boolean(target && typeof target.closest === 'function' && target.closest('[data-no-biometrics]'));
  };

  addEventListener('keydown', (event) => {
    emit({ type: 'activity', key: event.code === 'PrintScreen' ? 'PrintScreen' : null });
    if (ignoredKey(event)) return;
    start();
    aggregator.keyDown(event.code, performance.now());
  }, { capture: true, passive: true });

  addEventListener('keyup', (event) => {
    if (event.isComposing) return;
    aggregator.keyUp(event.code, performance.now());
  }, { capture: true, passive: true });

  // Only a real mouse: touch and pen move differently and would blur the profile.
  addEventListener('pointermove', (event) => {
    emit({ type: 'activity' });
    if (event.pointerType !== 'mouse') return;
    start();
    aggregator.pointerMove(event.clientX, event.clientY, performance.now());
  }, { capture: true, passive: true });

  addEventListener('pointerdown', (event) => {
    emit({ type: 'activity' });
    if (event.pointerType !== 'mouse' || event.button !== 0) return;
    aggregator.pointerDown(performance.now());
  }, { capture: true, passive: true });

  addEventListener('pointerup', (event) => {
    if (event.pointerType !== 'mouse' || event.button !== 0) return;
    aggregator.pointerUp(performance.now());
  }, { capture: true, passive: true });

  addEventListener('blur', () => aggregator.releaseAll());

  // Same coarse fingerprint as telemetry.js, so both land on the same device row.
  function fingerprint() {
    const parts = [
      navigator.userAgent, navigator.platform || '', navigator.language || '',
      `${screen.width}x${screen.height}x${screen.colorDepth}`,
      String(navigator.hardwareConcurrency || 0),
      Intl.DateTimeFormat().resolvedOptions().timeZone || '',
    ].join('|');
    let hash = 0x811c9dc5;
    for (let i = 0; i < parts.length; i++) {
      hash ^= parts.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return `${hash.toString(16)}-${parts.length.toString(16)}`;
  }

  function send({ beacon = false } = {}) {
    const summary = aggregator.summary();
    const at = new Date(windowStartedAt || Date.now()).toISOString();
    aggregator.reset();
    windowStartedAt = null;
    if (!summary) return;

    const body = JSON.stringify({
      at, seconds: summary.seconds, keys: summary.keys, strokes: summary.strokes, features: summary.features,
      device: { fingerprint: fingerprint() },
    });
    if (beacon && navigator.sendBeacon) {
      navigator.sendBeacon(ENDPOINT, new Blob([body], { type: 'application/json' }));
      return;
    }
    if (sending) return;
    sending = true;
    fetch(ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, keepalive: true })
      .then(async (res) => {
        if (res.status === 401) {
          location.href = '/login';
          return;
        }
        const reply = res.ok ? await res.json() : null;
        // step-up.js shows the dialog; this script only reports that it is needed.
        if (reply && reply.stepUp) dispatchEvent(new CustomEvent('crimguard:step-up'));
      })
      .catch(() => { /* offline: this window is lost, the next one tries again */ })
      .finally(() => { sending = false; });
  }

  setInterval(() => {
    if (windowStartedAt === null) return;
    const now = Date.now();
    const idleFor = aggregator.lastAt === null ? 0 : performance.now() - aggregator.lastAt;
    const enough = aggregator.keys >= MIN_KEYS || aggregator.strokes >= MIN_STROKES;
    const full = aggregator.keys >= FULL_WINDOW_KEYS || aggregator.strokes >= FULL_WINDOW_STROKES;
    if (full || (enough && now - windowStartedAt >= WINDOW_MS) || (enough && idleFor >= IDLE_SEND_MS)) {
      send();
    } else if (!enough && now - windowStartedAt >= STALE_WINDOW_MS) {
      aggregator.reset(); // too little to judge; start again rather than stretch the window
      windowStartedAt = null;
    }
  }, TICK_MS);

  addEventListener('pagehide', () => send({ beacon: true }));

  window.CrimGuardBiometrics.live = () => ({ keys: aggregator.keys, strokes: aggregator.strokes, minKeys: MIN_KEYS, minStrokes: MIN_STROKES });
  window.CrimGuardBiometrics.flush = () => send();
})();
