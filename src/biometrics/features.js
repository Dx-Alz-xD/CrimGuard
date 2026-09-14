'use strict';

// The behavioural-biometrics feature vector: what one window of keyboard and pointer use is
// reduced to before it leaves the browser (public/static/biometrics.js computes it; this file is
// the server's copy of the definition).
//
// Two modalities, judged separately and then combined (model.js):
//
//   keys     Keys are never identified. Each physical key becomes a coarse zone the moment it is
//            pressed - left-hand letter, right-hand letter, space, backspace, shift side - and only
//            timings between zones are kept. Password fields are skipped entirely.
//   pointer  Positions never leave the page. Movement is cut into strokes (movement between
//            pauses or clicks) and only each stroke's speed, acceleration, straightness and
//            timing survive, plus how long a click is held and the pause before it.
//
// Every value is a robust statistic over the window (a median, an interquartile range or a
// rate), so one odd keypress or flick doesn't move it. `floor` is the smallest spread that is
// still a real difference for that feature; the profile never scales a deviation by less.

const MIN_KEYS = 40;
const MIN_STROKES = 15;

const KEY_FEATURES = Object.freeze([
  // How long keys are held, in ms.
  { key: 'dwellL', unit: 'ms', max: 1000, floor: 6, label: 'hold time, left-hand letters' },
  { key: 'dwellR', unit: 'ms', max: 1000, floor: 6, label: 'hold time, right-hand letters' },
  { key: 'dwellSpace', unit: 'ms', max: 1000, floor: 8, label: 'hold time, space bar' },
  { key: 'dwellIqr', unit: 'ms', max: 1000, floor: 5, label: 'spread of letter hold times' },
  // Key-down to next key-down, in ms, by which hand moved to which.
  { key: 'flightLL', unit: 'ms', max: 1500, floor: 12, label: 'left → left' },
  { key: 'flightLR', unit: 'ms', max: 1500, floor: 12, label: 'left → right' },
  { key: 'flightRL', unit: 'ms', max: 1500, floor: 12, label: 'right → left' },
  { key: 'flightRR', unit: 'ms', max: 1500, floor: 12, label: 'right → right' },
  { key: 'flightToSpace', unit: 'ms', max: 1500, floor: 12, label: 'letter → space' },
  { key: 'flightFromSpace', unit: 'ms', max: 1500, floor: 12, label: 'space → letter' },
  { key: 'flightIqr', unit: 'ms', max: 1500, floor: 10, label: 'spread of letter-to-letter timing' },
  // Habits.
  { key: 'rollover', unit: 'share', max: 1, floor: 0.03, label: 'keys pressed before the last was released' },
  { key: 'pauseRate', unit: 'share', max: 1, floor: 0.02, label: 'gaps of 1.5–10 s between keys' },
  { key: 'burstLength', unit: 'keys', max: 500, floor: 2, label: 'keys typed between pauses' },
  { key: 'correctionRate', unit: 'per 100 keys', max: 100, floor: 1, label: 'backspace and delete' },
  { key: 'rightShiftShare', unit: 'share', max: 1, floor: 0.08, label: 'right shift used instead of left' },
  { key: 'shiftLead', unit: 'ms', max: 1500, floor: 15, label: 'shift down to the letter' },
  { key: 'keysPerMinute', unit: 'keys/min', max: 1500, floor: 15, label: 'typing speed while typing' },
].map((feature) => Object.freeze({ ...feature, modality: 'keys' })));

const POINTER_FEATURES = Object.freeze([
  { key: 'pointerSpeed', unit: 'px/s', max: 20000, floor: 40, label: 'pointer speed during a movement' },
  { key: 'pointerSpeedIqr', unit: 'px/s', max: 20000, floor: 40, label: 'spread of pointer speed' },
  { key: 'pointerPeakSpeed', unit: 'px/s', max: 40000, floor: 80, label: 'peak speed of a movement' },
  { key: 'pointerAccel', unit: 'px/s²', max: 1000000, floor: 400, label: 'how sharply movements speed up and slow down' },
  { key: 'pointerStraightness', unit: 'share', max: 1, floor: 0.02, label: 'how straight movements are' },
  { key: 'pointerStrokeMs', unit: 'ms', max: 5000, floor: 25, label: 'length of a movement' },
  { key: 'clickHold', unit: 'ms', max: 2000, floor: 8, label: 'how long a click is held' },
  { key: 'clickPause', unit: 'ms', max: 2000, floor: 25, label: 'pause between stopping and clicking' },
].map((feature) => Object.freeze({ ...feature, modality: 'pointer' })));

const FEATURES = Object.freeze([...KEY_FEATURES, ...POINTER_FEATURES]);
const MODALITIES = Object.freeze({
  keys: Object.freeze({ features: KEY_FEATURES, minEvidence: MIN_KEYS, evidence: 'keys' }),
  pointer: Object.freeze({ features: POINTER_FEATURES, minEvidence: MIN_STROKES, evidence: 'strokes' }),
});
const FEATURE_KEYS = Object.freeze(FEATURES.map((feature) => feature.key));
const FEATURE_BY_KEY = Object.freeze(Object.fromEntries(FEATURES.map((feature) => [feature.key, feature])));

module.exports = { MIN_KEYS, MIN_STROKES, KEY_FEATURES, POINTER_FEATURES, FEATURES, MODALITIES, FEATURE_KEYS, FEATURE_BY_KEY };
