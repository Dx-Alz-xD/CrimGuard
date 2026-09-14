'use strict';

// When to plant a decoy, when to raise the stakes, and when to take it away again.
//
//   score  < 25  stand down: withdraw every decoy (a trap left for someone no longer suspected
//                is entrapment waiting to happen, and a false positive in the making)
//   25–39        hysteresis: keep what is there, plant nothing new
//   40–59        tier 1 - a document
//   60–79        tier 2 - API keys
//   80+          tier 3 - credentials with admin or database reach
//
// Some scenarios raise the tier on their own once a decoy is warranted at all: someone
// abusing privilege is shown privileged credentials even at a medium score, because that is
// the thing their behaviour says they are after.
//
// A decoy nobody has touched in two weeks is rotated for a fresh one, so the same file isn't
// sitting there long enough to look suspicious. After a trip, nothing new is planted for a day:
// the account is under investigation and its sessions are gone.

// RED_HONEYTOKEN_SCORE is the same threshold the decoy projects use (src/telemetry/honeytokens.js).
const PLANT_FROM = Number(process.env.RED_HONEYTOKEN_SCORE) || 40;

const POLICY = Object.freeze({
  plantFrom: PLANT_FROM,
  standDownBelow: 25,
  tiers: Object.freeze([
    Object.freeze({ tier: 1, minScore: PLANT_FROM }),
    Object.freeze({ tier: 2, minScore: 60 }),
    Object.freeze({ tier: 3, minScore: 80 }),
  ]),
  scenarioTiers: Object.freeze({
    pre_resignation_hoarding: 2,
    slow_exfiltration: 2,
    shadow_ai_leak: 2,
    privilege_abuse: 3,
    credential_compromise: 3,
  }),
  maxActive: 2,
  rotateAfterDays: 14,
  cooldownAfterTripHours: 24,
  // Opening a decoy is recorded as an access to a restricted file, which the risk engine
  // already weighs. It is not a trip: a curious person opens a file and closes it. Add
  // 'opened' here for the strict reading, where any access at all counts.
  tripOn: Object.freeze(['copied', 'exfiltrated', 'key_used']),
});

function targetTier(score, scenario, P = POLICY) {
  if (!(Number(score) >= P.plantFrom)) return 0;
  let tier = 0;
  for (const { tier: t, minScore } of P.tiers) if (score >= minScore) tier = Math.max(tier, t);
  return Math.max(tier, P.scenarioTiers[scenario] ?? 0);
}

// active: [{ id, tier, plantedAt }]. Returns { tier, plant, retire: [{ id, reason }] }.
function decide({ score, scenario, active = [], lastTripAt = null, now = Date.now() }, P = POLICY) {
  if (score === null || score === undefined || !(Number(score) >= P.standDownBelow)) {
    return { tier: 0, plant: false, retire: active.map(({ id }) => ({ id, reason: 'stood_down' })) };
  }

  const retire = active
    .filter(({ plantedAt }) => now - Date.parse(plantedAt) >= P.rotateAfterDays * 86400000)
    .map(({ id }) => ({ id, reason: 'rotated' }));
  const remaining = active.filter(({ id }) => !retire.some((r) => r.id === id));

  const tier = targetTier(score, scenario, P);
  const coolingDown = lastTripAt !== null && now - Date.parse(lastTripAt) < P.cooldownAfterTripHours * 3600000;
  const plant = tier > 0 && !coolingDown && remaining.length < P.maxActive && !remaining.some((a) => a.tier >= tier);
  return { tier, plant, retire, coolingDown };
}

module.exports = { POLICY, targetTier, decide };
