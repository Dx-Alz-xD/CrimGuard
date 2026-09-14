'use strict';

const { createRiskEngine, loadFeatureCatalog } = require('../../crimguard/risk');
const { sampler, weekdays, addDays, ordinaryFeatures } = require('../../crimguard/risk/scenarios');

const catalog = loadFeatureCatalog();
const engine = createRiskEngine({ catalog });

// Weekday snapshots of an ordinary analyst. `edits` maps a position counted from the end
// (0 = the last day) to changes for that day: { features, context, honeytokenTrips, ... }.
function userDays({ seed = 1, calendarDays = 150, assetWeight = 4, edits = {}, features } = {}) {
  const s = sampler(seed);
  const days = weekdays('2026-01-05', calendarDays).map((date) => ({
    date,
    assetWeight,
    features: features ? features(s) : ordinaryFeatures(s),
  }));
  for (const [fromEnd, edit] of Object.entries(edits)) {
    const day = days[days.length - 1 - Number(fromEnd)];
    const { features: changes, ...rest } = edit;
    Object.assign(day, rest);
    Object.assign(day.features, changes);
  }
  return days;
}

const lastDate = (days) => days[days.length - 1].date;
const scoreAll = (days, options = {}, e = engine) => e.scoreTimeline({ days, ...options });
const scoreLast = (days, options = {}, e = engine) => scoreAll(days, options, e).at(-1);
const contribution = (result, feature) => result.contributions.find((c) => c.feature === feature);

module.exports = { catalog, engine, userDays, lastDate, scoreAll, scoreLast, contribution, addDays, sampler, weekdays };
