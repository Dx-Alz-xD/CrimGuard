'use strict';

// Every API route, registered in one place. A new feature adds a line here rather than to
// src/app.js. No two routes match the same method and path, so the order does not matter.

const { registerAuthRoutes } = require('./auth');
const { registerProfileRoutes } = require('./profile');
const { registerProjectRoutes } = require('./projects');
const { registerFileRoutes } = require('./files');
const { registerAdminRoutes } = require('./admin');
const { registerTelemetryRoutes } = require('./telemetry');
const { registerCrimGuardRoutes } = require('./crimguard');
const { registerStepUpRoutes } = require('./step-up');
const { registerEgressRoutes } = require('./egress');

function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
  registerProfileRoutes(router, deps);
  registerProjectRoutes(router, deps);
  registerFileRoutes(router, deps);
  registerAdminRoutes(router, deps);
  registerTelemetryRoutes(router, deps);
  registerStepUpRoutes(router, deps);
  registerEgressRoutes(router, deps);
  // Identity throttle, biometrics and honeytrapping (src/protection/).
  deps.protection.register(router, deps);
  registerCrimGuardRoutes(router, deps);
}

module.exports = { registerRoutes };
