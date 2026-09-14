'use strict';

// Simulated people for the biometrics tests. Each has a stable style at the keyboard (hold times,
// hand-to-hand timing, rollover, pauses, corrections, shift habits) and with the mouse (how fast
// they cover a distance, how curved and how front-loaded a movement is, tremor, overshoot, how
// long they pause before clicking and hold the button). Every sitting drifts a little from it,
// the way the same person is different on a Monday morning.
//
// Keystrokes and pointer movements are replayed through the real browser aggregator from
// public/static/biometrics.js, so the tests exercise exactly what the page will send.

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SCRIPT = path.join(__dirname, '..', 'public', 'static', 'biometrics.js');

function loadAggregator() {
  const window = {};
  vm.runInNewContext(fs.readFileSync(SCRIPT, 'utf8'), { window, document: { body: { dataset: { page: 'test' } } } });
  return window.CrimGuardBiometrics.createAggregator;
}

function rng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  next.normal = () => Math.sqrt(-2 * Math.log(1 - next())) * Math.cos(2 * Math.PI * next());
  next.pick = (list) => list[Math.floor(next() * list.length)];
  return next;
}

const LEFT = ['KeyQ', 'KeyW', 'KeyE', 'KeyR', 'KeyT', 'KeyA', 'KeyS', 'KeyD', 'KeyF', 'KeyG', 'KeyZ', 'KeyX', 'KeyC', 'KeyV', 'KeyB'];
const RIGHT = ['KeyY', 'KeyU', 'KeyI', 'KeyO', 'KeyP', 'KeyH', 'KeyJ', 'KeyK', 'KeyL', 'KeyN', 'KeyM'];
const clamp = (value, min, max = Infinity) => Math.min(max, Math.max(min, value));

// --- the keyboard ------------------------------------------------------------------------------

function makeTypist(seed) {
  const r = rng(seed);
  const n = r.normal;
  const tempo = Math.exp(0.3 * n());
  const base = 165 * tempo;
  return {
    seed,
    dwell: { L: clamp(88 + 16 * n(), 45), R: clamp(88 + 16 * n(), 45), S: clamp(98 + 18 * n(), 50) },
    dwellSpread: 0.16 + 0.05 * Math.abs(n()),
    flight: {
      LL: clamp(base * (1 + 0.12 * n()), 60), LR: clamp(base * (0.85 + 0.1 * n()), 50),
      RL: clamp(base * (0.85 + 0.1 * n()), 50), RR: clamp(base * (1 + 0.12 * n()), 60),
      XS: clamp(base * (1 + 0.15 * n()), 60), SX: clamp(base * (1.1 + 0.15 * n()), 60),
    },
    flightSpread: 0.22 + 0.08 * Math.abs(n()),
    pause: 0.02 + 0.02 * Math.abs(n()),
    correction: 0.015 + 0.025 * Math.abs(n()),
    capital: 0.05,
    rightShift: r(),
    shiftLead: clamp(105 + 30 * n(), 40),
  };
}

// --- the mouse ---------------------------------------------------------------------------------

function makeMover(seed) {
  const r = rng(seed * 7919 + 17);
  const n = r.normal;
  return {
    seed,
    fittsA: clamp(90 + 20 * n(), 30),                // ms before a movement gets going
    fittsB: clamp(120 * Math.exp(0.18 * n()), 50),   // ms per bit of difficulty
    curvature: 0.04 + 0.06 * Math.abs(n()),           // how far the path bows, as a share of the distance
    peakAt: clamp(0.42 + 0.05 * n(), 0.25, 0.6),     // where in the movement the speed peaks
    overshoot: clamp(0.12 + 0.06 * n(), 0, 0.5),      // chance of a small corrective movement
    tremor: 0.3 + 0.3 * Math.abs(n()),               // px of jitter per sample
    clickHold: clamp(95 + 15 * n(), 45),
    clickPause: clamp(230 + 60 * n(), 60),
    timeSpread: 0.18 + 0.05 * Math.abs(n()),
    sampleMs: r() < 0.5 ? 8 : 16,                    // 125 Hz mouse, or one event per frame
  };
}

// One sitting: the style with this session's drift applied.
function session(person, seed) {
  const r = rng(seed);
  return {
    person, typist: person.typist || person, mover: person.mover || null, r,
    flightDrift: 1 + 0.05 * r.normal(), dwellDrift: 1 + 0.04 * r.normal(),
    moveDrift: 1 + 0.08 * r.normal(), clickDrift: 1 + 0.08 * r.normal(),
  };
}

// A person with both styles.
const makePerson = (seed) => ({ seed, typist: makeTypist(seed), mover: makeMover(seed) });

function typeEvents(sitting, keys, events, startAt = 1000) {
  const { typist: p, r, flightDrift, dwellDrift } = sitting;
  const lognormal = (sigma) => Math.exp(sigma * r.normal());
  let t = startAt;
  let previous = 'L';
  for (let i = 0; i < keys; i++) {
    let zone;
    const roll = r();
    if (roll < p.correction) zone = 'B';
    else if (roll < p.correction + 0.18 && previous !== 'S') zone = 'S';
    else zone = r() < 0.56 ? 'L' : 'R';

    const pair = (previous === 'L' || previous === 'R') && (zone === 'L' || zone === 'R') ? previous + zone
      : zone === 'S' ? 'XS' : previous === 'S' ? 'SX' : 'LL';
    let gap = p.flight[pair] * flightDrift * lognormal(p.flightSpread);
    if (r() < p.pause) gap += 1500 + 4000 * r();
    t += gap;

    const code = zone === 'L' ? r.pick(LEFT) : zone === 'R' ? r.pick(RIGHT) : zone === 'S' ? 'Space' : 'Backspace';
    const hold = (zone === 'S' ? p.dwell.S : zone === 'B' ? 90 : p.dwell[zone]) * dwellDrift * lognormal(p.dwellSpread);

    if ((zone === 'L' || zone === 'R') && r() < p.capital) {
      const shift = r() < p.rightShift ? 'ShiftRight' : 'ShiftLeft';
      const shiftDown = t - p.shiftLead * lognormal(0.2);
      events.push({ type: 'keyDown', args: [shift], t: shiftDown }, { type: 'keyUp', args: [shift], t: t + hold + 15 });
    }
    events.push({ type: 'keyDown', args: [code], t }, { type: 'keyUp', args: [code], t: t + hold });
    previous = zone === 'B' ? previous : zone;
  }
  return t;
}

function moveEvents(sitting, strokes, events, startAt = 1000) {
  const { mover: m, r, moveDrift, clickDrift } = sitting;
  const lognormal = (sigma) => Math.exp(sigma * r.normal());
  let t = startAt;
  let x = 600;
  let y = 400;
  const minJerk = (s) => 10 * s ** 3 - 15 * s ** 4 + 6 * s ** 5;
  const skew = Math.log(0.5) / Math.log(m.peakAt);

  for (let i = 0; i < strokes; i++) {
    const distance = Math.exp(Math.log(60) + r() * (Math.log(900) - Math.log(60)));
    const width = 24 + 20 * r();
    const duration = (m.fittsA + m.fittsB * Math.log2(distance / width + 1)) * moveDrift * lognormal(m.timeSpread);
    const angle = r() * 2 * Math.PI;
    const ex = x + distance * Math.cos(angle);
    const ey = y + distance * Math.sin(angle);
    const bow = m.curvature * distance * lognormal(0.3) * (r() < 0.5 ? -1 : 1);
    const cx = (x + ex) / 2 - Math.sin(angle) * bow;
    const cy = (y + ey) / 2 + Math.cos(angle) * bow;

    const steps = Math.max(4, Math.round(duration / m.sampleMs));
    for (let k = 1; k <= steps; k++) {
      const u = minJerk((k / steps) ** skew);
      const px = (1 - u) ** 2 * x + 2 * (1 - u) * u * cx + u * u * ex + m.tremor * r.normal();
      const py = (1 - u) ** 2 * y + 2 * (1 - u) * u * cy + u * u * ey + m.tremor * r.normal();
      events.push({ type: 'pointerMove', args: [px, py], t: t + (k * duration) / steps });
    }
    t += duration;
    x = ex;
    y = ey;

    if (r() < m.overshoot) {
      // A small correction straight after, close enough in time to count as the same stroke.
      const cx2 = x + (5 + 20 * r()) * (r() < 0.5 ? -1 : 1);
      const cy2 = y + (5 + 20 * r()) * (r() < 0.5 ? -1 : 1);
      const cd = 60 + 60 * r();
      for (let k = 1; k <= 5; k++) {
        events.push({ type: 'pointerMove', args: [x + ((cx2 - x) * k) / 5, y + ((cy2 - y) * k) / 5], t: t + 40 + (k * cd) / 5 });
      }
      t += 40 + cd;
      x = cx2;
      y = cy2;
    }

    if (r() < 0.75) {
      t += m.clickPause * clickDrift * lognormal(0.25);
      const hold = m.clickHold * clickDrift * lognormal(0.18);
      events.push({ type: 'pointerDown', args: [], t }, { type: 'pointerUp', args: [], t: t + hold });
      t += hold;
    }
    t += 300 + 1200 * r();
  }
  return t;
}

// Types `keys` keystrokes and moves through `strokes` pointer strokes (interleaved in time as
// separate stretches), then returns the aggregator's window summary.
function simulateWindow(sitting, Aggregator, { keys = 0, strokes = 0 } = {}) {
  const events = [];
  let t = 1000;
  if (keys && sitting.typist) t = typeEvents(sitting, keys, events, t) + 800;
  if (strokes && sitting.mover) moveEvents(sitting, strokes, events, t);
  const aggregator = Aggregator();
  events.sort((a, b) => a.t - b.t || (a.type.endsWith('Up') ? -1 : 1));
  for (const e of events) aggregator[e.type](...e.args, e.t);
  return aggregator.summary();
}

// The keyboard-only shorthand the older tests use.
const typeWindow = (sitting, Aggregator, keys = 140) => simulateWindow(sitting, Aggregator, { keys });

module.exports = { loadAggregator, makeTypist, makeMover, makePerson, session, simulateWindow, typeWindow, rng };
