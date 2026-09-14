'use strict';

const {
  MODEL_VERSION, PARAMS, CATEGORY_WEIGHTS, FEATURE_WEIGHTS, SEQUENCE_STAGES, SHADOW_AI_FEATURES,
} = require('./params');
const {
  dayNumber, decay, isNumber, median, robustStats, TRANSFORMS, scaleFloor, directional, cusum,
  inverseNormalCdf, tToZ, anomalyStrength, noisyOr, clamp, round,
} = require('./stats');
const { SCORABLE_TYPES } = require('./catalog');
const { contextConfidence } = require('./context');
const { hrAmplifier } = require('./amplifier');

// The CrimGuard risk formula, v2. README.md walks through every step. In short, per feature f:
//
//   r_f = W_f × I_f × A_f × (1 − C_f)       weight × impact × anomaly strength × unexplained share
//
// then, for the day:
//
//   r̃_f   = max(r_f today, r_f on an earlier day × 2^(−age / 3 days))     signals keep counting a while
//   R     = noisy-OR over categories of (discounted noisy-OR of the category's r̃_f)
//   R'    = 1 − (1 − R)^H                                                   HR stressors, H ∈ [1, 2]
//   score = max(100 × R', floor)                                            honeytoken floor = 100

const NO_CONTEXT = Object.freeze({ confidence: 0, source: null, ref: null, factors: null });
const DETECTION_METHOD = { self: 'z_score', peer: 'z_score', drift: 'drift_trend', flag: 'rule' };

const toFlag = (v) => (v === true || v === 1 ? true : v === false || v === 0 ? false : null);

function createRiskEngine({ catalog, orgSettings = {}, params = PARAMS, modelVersion = MODEL_VERSION } = {}) {
  if (!Array.isArray(catalog) || !catalog.length) throw new TypeError('createRiskEngine needs the feature catalog');
  const P = params;
  const { zMin } = P.anomaly;

  const indicators = catalog
    .filter((f) => f.signalRole === 'indicator' && SCORABLE_TYPES.has(f.valueType) && orgSettings[f.key]?.isEnabled !== false)
    .map((f) => {
      const own = orgSettings[f.key] ?? {};
      const fallbackThreshold = f.valueType === 'flag' ? P.flags.threshold : P.anomaly.defaultThreshold;
      return {
        ...f,
        weight: clamp(own.weight ?? FEATURE_WEIGHTS[f.key] ?? CATEGORY_WEIGHTS[f.category] ?? 0.5, 0, 1),
        threshold: Math.max(own.zThreshold ?? f.zThreshold ?? fallbackThreshold, zMin + 0.1),
      };
    });

  const lookbackDays = Math.max(P.baseline.rollingDays, P.flags.windowDays, P.drift.anchorFromDaysAgo, P.drift.recentDays);

  // Earlier values of every feature as [{ d, v }], oldest first. Days on or after `t` are ignored.
  function buildSeries(history, t) {
    const series = new Map();
    for (const day of history) {
      const d = dayNumber(day.date);
      if (d >= t) continue;
      for (const [key, v] of Object.entries(day.features ?? {})) {
        if (v == null) continue;
        if (!series.has(key)) series.set(key, []);
        series.get(key).push({ d, v });
      }
    }
    for (const list of series.values()) list.sort((a, b) => a.d - b.d);
    return series;
  }

  const between = (past, from, to) => past.filter((p) => p.d >= from && p.d < to && isNumber(p.v)).map((p) => p.v);

  function evaluateNumeric(meta, x, t, past, peerValues, anchor) {
    const T = TRANSFORMS[meta.valueType];
    const floor = (center) => scaleFloor(meta.valueType, center, P.scaleFloor);
    const B = P.baseline;
    // z against a baseline, corrected for how many days its spread was estimated from (Student t).
    const zAgainst = (value, { median: center, scale, n }) =>
      tToZ(directional((value - center) / Math.max(scale, floor(center)), meta.direction), B.madEfficiency * n - 1);

    // Self baseline, shrunk towards the peer group while the user's own history is short.
    const rolling = between(past, t - B.rollingDays, t);
    const own = rolling.length ? robustStats(rolling.map(T)) : null;
    const peerRaw = (peerValues ?? []).filter(isNumber);
    const peer = peerRaw.length >= B.minPeerSamples ? robustStats(peerRaw.map(T)) : null;

    let base = null;
    if (own && peer) {
      const w = own.n / (own.n + B.peerPriorDays);
      base = { median: w * own.median + (1 - w) * peer.median, scale: w * own.scale + (1 - w) * peer.scale, n: own.n + peer.n, ownWeight: w };
    } else if (own && own.n >= B.minSamples) {
      base = { ...own, ownWeight: 1 };
    } else if (peer) {
      base = { ...peer, ownWeight: 0 };
    }

    const y = T(x);
    const out = {
      baselineDays: rolling.length,
      baselineMedian: rolling.length ? median(rolling) : peerRaw.length ? median(peerRaw) : null,
      ownWeight: base?.ownWeight ?? null,
      z: {},
      strength: {},
      cusum: null,
      driftPctVsAnchor: null,
    };

    if (base) {
      out.z.self = zAgainst(y, base);
      out.strength.self = anomalyStrength(out.z.self, meta.threshold, zMin);
    }
    // Deviation from peers on its own is weaker evidence: some people are just busier than their team.
    if (peer && base?.ownWeight > 0) {
      out.z.peer = zAgainst(y, peer);
      out.strength.peer = P.anomaly.peerOnlyCap * anomalyStrength(out.z.peer, meta.threshold, zMin);
    }

    // Drift against a frozen reference window. The rolling baseline absorbs slow creep (Case B);
    // this doesn't. CUSUM proves the shift is sustained, the 2-week level proves it is large, and
    // the weaker of the two sets the strength, so neither a sustained +10% nor a one-day spike passes.
    const D = P.drift;
    const anchorRaw = between(past, anchor.from, anchor.to);
    const levelRaw = between(past, t - D.levelDays + 1, t).concat(x);
    if (anchorRaw.length >= D.minAnchorSamples && levelRaw.length >= D.minLevelSamples) {
      const ref = robustStats(anchorRaw.map(T));
      const scale = Math.max(ref.scale, floor(ref.median));
      const standardize = (v) => directional((v - ref.median) / scale, meta.direction);
      const recent = between(past, t - D.recentDays + 1, t).concat(x);
      const s = cusum(recent.map((v) => standardize(T(v))), D.cusumK);
      const zLevel = zAgainst(median(levelRaw.map(T)), ref);

      out.cusum = s / D.cusumH;
      out.z.drift = Math.min(meta.threshold * out.cusum, zLevel);
      out.strength.drift = anomalyStrength(out.z.drift, meta.threshold, zMin);
      const anchorMedian = median(anchorRaw);
      out.driftPctVsAnchor = anchorMedian > 0 ? median(levelRaw) / anchorMedian - 1 : null;
    }
    return out;
  }

  // How surprising is it that this flag is set today? Beta-smoothed rate from the user's last
  // 90 days (prior: the peer rate), turned into the z-score of an event that rare.
  function evaluateFlag(meta, x, t, past, peerValues) {
    const F = P.flags;
    const window = past.filter((p) => p.d >= t - F.windowDays && p.d < t && toFlag(p.v) != null);
    const hits = window.filter((p) => toFlag(p.v)).length;
    const peerFlags = (peerValues ?? []).map(toFlag).filter((v) => v != null);
    const prior = peerFlags.length >= P.baseline.minPeerSamples ? peerFlags.filter(Boolean).length / peerFlags.length : F.priorRate;
    const rate = (hits + F.priorStrength * Math.max(prior, 1e-3)) / (window.length + F.priorStrength);
    const z = x ? inverseNormalCdf(1 - rate) : 0;
    return {
      baselineDays: window.length,
      baselineRate: rate,
      z: { self: z },
      strength: { self: x ? anomalyStrength(z, meta.threshold, zMin) : 0 },
    };
  }

  // Features in one category move together (a bulk copy raises files, MB and confidential hits at
  // once), so within a category the 2nd strongest counts half and the 3rd a quarter. Categories are
  // independent evidence. In log space all of it is a sum; item.log is each item's share of it.
  function aggregate(items) {
    const groups = new Map();
    for (const item of items) {
      if (!groups.has(item.category)) groups.set(item.category, []);
      groups.get(item.category).push(item);
    }
    const categories = [];
    for (const [category, members] of groups) {
      members.sort((a, b) => b.risk - a.risk);
      const discounted = members.map((m, i) => m.risk * P.aggregation.secondaryDiscount ** i);
      members.forEach((m, i) => { m.log = -Math.log1p(-Math.min(discounted[i], 1 - 1e-12)); });
      categories.push({ category, risk: noisyOr(discounted) });
    }
    categories.sort((a, b) => b.risk - a.risk);
    return { score: noisyOr(categories.map((c) => c.risk)), categories };
  }

  function scoreDay({ subject = {}, day, history = [], peers = {}, previous = [] }) {
    const t = dayNumber(day.date);
    const features = day.features ?? {};
    const series = buildSeries(history, t);
    const anchor = subject.anchorPeriod
      ? { from: dayNumber(subject.anchorPeriod.start), to: dayNumber(subject.anchorPeriod.end) + 1 }
      : { from: t - P.drift.anchorFromDaysAgo, to: t - P.drift.anchorToDaysAgo };
    const S = P.sensitivity;
    const dayAssetWeight = clamp(day.assetWeight ?? S.default, 1, S.max);

    // 1. Every indicator: detectors → strength A, then weight W, impact I, context C, risk r.
    const evaluations = [];
    let missing = 0;
    for (const meta of indicators) {
      const raw = features[meta.key];
      const past = series.get(meta.key) ?? [];
      let ev;
      if (meta.valueType === 'flag') {
        const x = toFlag(raw);
        if (x == null) { missing++; continue; }
        ev = evaluateFlag(meta, x, t, past, peers[meta.key]);
      } else {
        if (!isNumber(raw)) { missing++; continue; }
        ev = evaluateNumeric(meta, raw, t, past, peers[meta.key], anchor);
      }

      const pointStrength = Math.max(ev.strength.self ?? 0, ev.strength.peer ?? 0);
      const strength = Math.max(pointStrength, ev.strength.drift ?? 0);
      let detector = null;
      if (strength > 0) {
        if (meta.valueType === 'flag') detector = 'flag';
        else if ((ev.strength.drift ?? 0) > pointStrength) detector = 'drift';
        else detector = (ev.strength.self ?? 0) >= (ev.strength.peer ?? 0) ? 'self' : 'peer';
      }

      const assetWeight = clamp(day.featureAssetWeights?.[meta.key] ?? dayAssetWeight, 1, S.max);
      let impact = assetWeight / S.max;
      if (subject.isPrivileged && S.privilegedCategories.includes(meta.category)) impact = Math.min(1, impact + S.privilegedBoost);

      const context = strength > 0
        ? contextConfidence({
          meta, observed: Number(raw), baselineMedian: ev.baselineMedian, date: day.date, context: day.context, snapshotFeatures: features,
        }, P.context)
        : NO_CONTEXT;

      evaluations.push({
        meta, observed: raw, ev, strength, detector, assetWeight, impact, context,
        risk: meta.weight * impact * strength * (1 - context.confidence),
      });
    }
    const anomalous = evaluations.filter((e) => e.strength > 0);

    // 2. Evidence that isn't one feature: a collect → stage → exfiltrate chain on the same day, and
    //    the multivariate Isolation Forest score computed upstream.
    const active = [];
    for (const [stage, keys] of Object.entries(SEQUENCE_STAGES)) {
      const best = anomalous.filter((e) => keys.includes(e.meta.key)).sort((a, b) => b.strength - a.strength)[0];
      if (best && best.strength >= P.sequence.stageStrength) active.push({ stage, e: best });
    }
    let sequenceRisk = 0;
    if (active.length >= 2) {
      const impact = Math.max(...active.map((a) => a.e.impact));
      const explained = Math.min(...active.map((a) => a.e.context.confidence));
      sequenceRisk = P.sequence.weight * impact * (1 - explained) * (active.length - 1) / (Object.keys(SEQUENCE_STAGES).length - 1);
    }

    const IF = P.isolationForest;
    const ifScore = isNumber(day.isolationForestScore) ? clamp(day.isolationForestScore, 0, 1) : null;
    const ifStrength = ifScore == null || ifScore <= IF.normalBelow ? 0 : 1 - 2 ** (-(ifScore - IF.normalBelow) / IF.halfStrengthStep);
    const ifImpact = anomalous.length ? Math.max(...anomalous.map((e) => e.impact)) : dayAssetWeight / S.max;
    const ifExplained = anomalous.length ? Math.min(...anomalous.map((e) => e.context.confidence)) : 0;
    const ifRisk = IF.weight * ifImpact * ifStrength * (1 - ifExplained);

    const todayItems = anomalous.filter((e) => e.risk > 0)
      .map((e) => ({ key: e.meta.key, category: e.meta.category, risk: e.risk, evaluation: e }));
    if (sequenceRisk > 0) todayItems.push({ key: 'exfiltration_sequence', category: 'exfiltration_sequence', risk: sequenceRisk });
    if (ifRisk > 0) todayItems.push({ key: 'multivariate', category: 'multivariate', risk: ifRisk });
    const todayScore = aggregate(todayItems.map((i) => ({ ...i }))).score;

    // 3. Signals from the last two weeks keep counting, decayed. Per feature only the strongest
    //    value survives, so a sustained anomaly isn't re-counted every day.
    const A = P.accumulation;
    const carried = new Map();
    for (const prev of previous) {
      const age = t - dayNumber(prev.date);
      if (age < 1 || age >= A.windowDays) continue;
      for (const c of prev.carry ?? []) {
        const risk = c.risk * decay(age, A.halfLifeDays);
        if (risk > (carried.get(c.key)?.risk ?? 0)) carried.set(c.key, { category: c.category, risk, from: prev.date });
      }
    }
    const items = todayItems.map((item) => {
      const c = carried.get(item.key);
      return c && c.risk > item.risk ? { ...item, risk: c.risk, carriedFrom: c.from } : { ...item };
    });
    for (const [key, c] of carried) {
      if (!todayItems.some((i) => i.key === key)) items.push({ key, category: c.category, risk: c.risk, carriedFrom: c.from });
    }
    const combined = aggregate(items);

    // 4. HR amplifier, then hard floors.
    const hr = hrAmplifier({ subject, date: day.date, features }, P.hr);
    const amplified = 1 - (1 - combined.score) ** hr.value;
    const beforeFloor = 100 * amplified;

    const honeytoken = (day.honeytokenTrips ?? 0) > 0;
    let floor = honeytoken ? { reason: 'honeytoken', score: P.floors.honeytoken } : null;
    if (!floor) {
      for (const [key, score] of Object.entries(P.floors.features)) {
        if (toFlag(features[key]) && (!floor || score > floor.score)) floor = { reason: key, score };
      }
    }
    const floorApplied = floor != null && floor.score > beforeFloor;
    const finalScore = round(clamp(floorApplied ? floor.score : beforeFloor, 0, 100), 2);
    const L = P.levels;
    const riskLevel = finalScore >= L.critical ? 'critical' : finalScore >= L.high ? 'high' : finalScore >= L.medium ? 'medium' : 'low';

    // 5. Explanation: split the score into points per item. −ln(1 − R) is the sum of the items'
    //    logs and H scales them all equally, so the points add up to the score exactly.
    const totalLog = items.reduce((sum, i) => sum + i.log, 0);
    const pointsFor = (log) => (totalLog > 0 ? round(beforeFloor * (log / totalLog), 2) : 0);
    const contributions = items.map((item) => ({ ...describe(item), points: pointsFor(item.log) }));
    if (floorApplied) contributions.push({ feature: floor.reason, category: 'floor', points: round(floor.score - beforeFloor, 2) });
    contributions.sort((a, b) => b.points - a.points);

    const evidence = anomalous.reduce((sum, e) => sum + e.meta.weight * e.impact * e.strength, 0);
    const kept = anomalous.reduce((sum, e) => sum + e.risk, 0);
    const numericZ = evaluations.filter((e) => e.meta.valueType !== 'flag' && isNumber(e.ev.z.self)).map((e) => e.ev.z.self);
    const cusums = evaluations.map((e) => e.ev.cusum).filter(isNumber);
    const components = {
      statisticalAnomalyScore: round(numericZ.length ? Math.max(...numericZ) : 0, 3),
      isolationForestScore: ifScore,
      driftScore: cusums.length ? round(Math.max(...cusums), 3) : null,
      assetCriticalityWeight: anomalous.length ? Math.max(...anomalous.map((e) => e.assetWeight)) : dayAssetWeight,
      contextMultiplier: evidence > 0 ? round(kept / evidence, 3) : 1,
      hrAmplifier: round(hr.value, 2),
      honeytokenOverride: honeytoken,
    };

    const top = [...items].sort((a, b) => b.risk - a.risk)[0];
    const scenario = classify({
      honeytoken, finalScore, hr, floor: floorApplied ? floor : null, sequenceRisk, top,
      explainedToday: anomalous.length > 0 && components.contextMultiplier <= 0.5,
    });

    const baselineDays = evaluations.map((e) => e.ev.baselineDays);
    const medianBaselineDays = baselineDays.length ? median(baselineDays) : 0;

    return {
      modelVersion,
      date: day.date,
      finalScore,
      riskLevel,
      scenario,
      scores: { today: round(todayScore, 4), combined: round(combined.score, 4), amplified: round(amplified, 4) },
      components,
      categories: combined.categories.map((c) => ({ category: c.category, risk: round(c.risk, 4) })),
      contributions,
      hrFactors: hr.factors.map((f) => ({ reason: f.reason, boost: round(f.boost, 3) })),
      floor: floorApplied ? floor : null,
      exfiltrationSequence: active.map((a) => a.stage),
      // What later days need from this one (store it with the score).
      carry: todayItems.map((i) => ({ key: i.key, category: i.category, risk: round(i.risk, 6) })),
      dataQuality: {
        featuresScored: evaluations.length,
        featuresMissing: missing,
        coverage: round(evaluations.length / Math.max(1, evaluations.length + missing), 3),
        medianBaselineDays,
        lowConfidence: medianBaselineDays < P.baseline.minSamples,
      },
    };
  }

  function describe(item) {
    const e = item.evaluation;
    const base = { feature: item.key, category: item.category, risk: round(item.risk, 4) };
    if (item.carriedFrom) base.carriedFrom = item.carriedFrom;
    if (!e) return base;
    return {
      ...base,
      detector: e.detector,
      detectionMethod: DETECTION_METHOD[e.detector],
      observed: e.observed,
      baselineMedian: round(e.ev.baselineMedian, 3),
      baselineRate: round(e.ev.baselineRate, 4),
      baselineDays: e.ev.baselineDays,
      ownWeight: round(e.ev.ownWeight, 3),
      z: { self: round(e.ev.z.self, 3), peer: round(e.ev.z.peer, 3), drift: round(e.ev.z.drift, 3) },
      zThreshold: e.meta.threshold,
      cusum: round(e.ev.cusum, 3),
      driftPctVsAnchor: round(e.ev.driftPctVsAnchor, 3),
      strength: round(e.strength, 4),
      weight: e.meta.weight,
      impact: round(e.impact, 3),
      assetWeight: e.assetWeight,
      context: { ...e.context, confidence: round(e.context.confidence, 4) },
    };
  }

  function classify({ honeytoken, finalScore, hr, floor, sequenceRisk, top, explainedToday }) {
    if (honeytoken) return 'honeytoken_trip';
    if (!top && !floor) return null;
    if (finalScore < P.levels.medium) return explainedToday ? 'legitimate_spike' : null;

    const category = top?.category ?? null;
    const dataRelated = category === 'access_resource' || category === 'data_movement' || category === 'exfiltration_sequence';
    const departing = hr.factors.some((f) => ['departure', 'pto_dump', 'pto_dump_flag'].includes(f.reason));
    if (departing && (dataRelated || sequenceRisk > 0)) return 'pre_resignation_hoarding';
    if (floor?.reason === 'audit_log_modification_flag') return 'privilege_abuse';
    if (floor?.reason === 'session_token_reuse_flag') return 'credential_compromise';
    if (!top) return 'other';
    if (SHADOW_AI_FEATURES.includes(top.key)) return 'shadow_ai_leak';
    // "Slow" means the daily detector no longer sees it: only the anchored baseline does.
    const e = top.evaluation;
    if (e?.detector === 'drift' && (e.ev.strength.self ?? 0) < 0.5 && dataRelated) return 'slow_exfiltration';
    if (['authentication_identity', 'device_network', 'behavioral_biometrics'].includes(category)) return 'credential_compromise';
    if (category === 'privilege_permission') return 'privilege_abuse';
    if (category === 'physical_environmental') return 'physical_security';
    return 'other';
  }

  // Scores consecutive days for one user, feeding each day into the next.
  // `days` are snapshots in any order; `peers` is an object or a function of the date.
  function scoreTimeline({ subject = {}, days, peers = {} }) {
    const sorted = [...days].sort((a, b) => dayNumber(a.date) - dayNumber(b.date));
    const dayNumbers = sorted.map((d) => dayNumber(d.date));
    const anchorStart = subject.anchorPeriod ? dayNumber(subject.anchorPeriod.start) : Infinity;
    const results = [];
    let start = 0;
    let recent = 0;

    for (let i = 0; i < sorted.length; i++) {
      const t = dayNumbers[i];
      while (dayNumbers[start] < Math.min(t - lookbackDays, anchorStart)) start++;
      while (dayNumbers[recent] <= t - P.accumulation.windowDays) recent++;
      const day = sorted[i];
      results.push(scoreDay({
        subject,
        day,
        history: sorted.slice(start, i),
        peers: typeof peers === 'function' ? peers(day.date) : peers,
        previous: results.slice(recent, i),
      }));
    }
    return results;
  }

  return { modelVersion, indicators, scoreDay, scoreTimeline };
}

// One row for the risk_scores table (database/crimguard/07_detection_scoring.sql).
function toRiskScoreRow(result, { snapshotId, userId }) {
  const c = result.components;
  return {
    snapshot_id: snapshotId,
    user_id: userId,
    model_version: result.modelVersion,
    statistical_anomaly_score: c.statisticalAnomalyScore,
    isolation_forest_score: c.isolationForestScore,
    drift_score: c.driftScore,
    asset_criticality_weight: c.assetCriticalityWeight,
    context_multiplier: c.contextMultiplier,
    hr_amplifier: c.hrAmplifier,
    honeytoken_override: c.honeytokenOverride,
    final_score: result.finalScore,
    risk_level: result.riskLevel,
    scenario: result.scenario,
    feature_contributions: Object.fromEntries(result.contributions.map((x) => [x.feature, x.points])),
    dashboard_payload: {
      scores: result.scores,
      categories: result.categories,
      contributions: result.contributions,
      hrFactors: result.hrFactors,
      floor: result.floor,
      exfiltrationSequence: result.exfiltrationSequence,
      carry: result.carry,
      dataQuality: result.dataQuality,
    },
  };
}

module.exports = { createRiskEngine, toRiskScoreRow };
