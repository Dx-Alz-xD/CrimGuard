'use strict';

// What the server does on a timer rather than in answer to a request.
//
//   housekeeping   hourly: expired sessions, old throttle rows, audit retention, spent challenges
//   risk           every quarter hour: aggregate and score today, and yesterday too, so a day
//                  that ended while the server was down still gets its snapshot once it is back

const HOUSEKEEPING_INTERVAL_MS = 60 * 60 * 1000;
// Often enough that the risk console shows today as it happens, cheap enough to leave running.
const RISK_INTERVAL_MS = 15 * 60 * 1000;
const DAY_MS = 86_400_000;

function startJobs({ stores, throttle, pow, limits, telemetry, crimguard, now = Date.now, riskInterval = RISK_INTERVAL_MS }) {
  function housekeeping() {
    try {
      stores.sessions.purgeExpired(now());
      throttle.purge(Math.max(...Object.values(limits).map((limit) => limit.windowMs)));
      stores.audit.purge();
      pow.purge();
      stores.signals.purge();
    } catch (err) {
      console.error('Housekeeping failed:', err);
    }
  }

  let running = false;
  async function runRisk() {
    if (running || !crimguard) return;
    running = true;
    try {
      await telemetry.flush();
      const day = new Date();
      await telemetry.runDay(day.toISOString().slice(0, 10));
      await telemetry.runDay(new Date(day.getTime() - DAY_MS).toISOString().slice(0, 10));
    } catch (err) {
      console.error('Risk scoring failed:', err.message);
    } finally {
      running = false;
    }
  }

  housekeeping();
  const timers = [setInterval(housekeeping, HOUSEKEEPING_INTERVAL_MS)];
  if (crimguard && riskInterval > 0) timers.push(setInterval(runRisk, riskInterval));
  for (const timer of timers) timer.unref();

  return {
    runRisk,
    stop: () => timers.forEach(clearInterval),
  };
}

module.exports = { RISK_INTERVAL_MS, startJobs };
