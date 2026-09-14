'use strict';

// Every tunable number in the CrimGuard risk formula lives here. See README.md for what each
// one does and where it comes from.
//
// Bump MODEL_VERSION whenever a value changes: risk_scores rows are unique per
// (snapshot_id, model_version), so scores from different formulas can sit side by side.
const MODEL_VERSION = 'cg-risk-2.0.0';

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

const PARAMS = deepFreeze({
  baseline: {
    rollingDays: 30,      // the user's "normal" is the 30 days before the scored day
    minSamples: 7,        // with fewer days and no peer group, the self detector abstains
    minPeerSamples: 5,
    peerPriorDays: 10,    // k in λ = n / (n + k): 10 days of own history weigh as much as the peer group
    // A MAD-based spread from n days is as precise as a standard deviation from 0.37·n days
    // (asymptotic relative efficiency 36.7%), which sets the Student-t degrees of freedom.
    madEfficiency: 0.37,
  },

  // Smallest spread a baseline may have, on the transformed scale. Stops a user whose count never
  // varies from producing an infinite z-score. Anscombe-transformed Poisson data has σ ≈ 1, so 1 is
  // the least spread real counts can have; log-scale floors of 0.2 mean "±22%".
  scaleFloor: {
    count: { abs: 1 },
    volume_mb: { abs: 0.2 },
    seconds: { abs: 0.2 },
    ratio: { abs: 0.02, rel: 0.1 },
    score: { abs: 0.1, rel: 0.1 },
  },

  anomaly: {
    zMin: 1.5,               // below this a deviation is noise and contributes nothing
    defaultThreshold: 3.0,   // used when the catalog has no default_z_threshold
    peerOnlyCap: 0.5,        // deviation from peers alone can reach at most half strength
  },

  flags: {
    windowDays: 90,          // rare events need a longer memory than counts
    priorRate: 0.05,         // assumed rate for a flag when there is no peer group
    priorStrength: 4,        // the prior counts as 4 days of evidence
    threshold: 2.326,        // z of a 1-in-100 event
  },

  drift: {
    anchorFromDaysAgo: 180,  // default frozen reference window: 180 to 90 days before the scored day
    anchorToDaysAgo: 90,
    minAnchorSamples: 20,
    recentDays: 28,          // CUSUM runs over the last 4 weeks
    levelDays: 14,           // effect size is the median of the last 2 weeks
    minLevelSamples: 7,
    cusumK: 0.5,             // allowance per day, in σ (Montgomery's standard choice)
    cusumH: 5,               // decision interval, in σ
  },

  isolationForest: {
    weight: 0.6,
    normalBelow: 0.55,       // Liu et al.: scores well under 0.5 are normal, near 1 are anomalies
    halfStrengthStep: 0.1,   // each +0.1 above normalBelow halves the distance to full strength
  },

  sensitivity: {
    default: 2,              // "internal" when nothing says what was touched
    max: 5,
    privilegedBoost: 0.2,    // blast radius: privileged accounts reach more
    privilegedCategories: ['authentication_identity', 'privilege_permission', 'device_network'],
  },

  context: {
    maxConfidence: 0.9,      // context never erases more than 90% of a risk
    reliability: { approvedTicket: 1, unapprovedTicket: 0.7, project: 0.7, roleChange: 0.6 },
    snapshotMitigator: 0.3,  // recent_role_change_flag / recent_project_assignment_flag with no details
    unknownScope: 0.7,
    unknownProportion: 0.6,
    proportionTolerance: 1.25,
    graceDaysBeforeAssignment: 1,
    ticketAfterEndHalfLifeDays: 3,
    roleChangeHalfLifeDays: 30,
    roleChangeMaxAgeDays: 90,
    ticketCategories: ['access_resource', 'data_movement', 'temporal', 'privilege_permission'],
    projectCategories: ['access_resource', 'data_movement', 'temporal', 'communication_collaboration'],
  },

  aggregation: {
    secondaryDiscount: 0.5,  // within a category the 2nd signal counts half, the 3rd a quarter...
  },

  sequence: {
    weight: 0.9,
    stageStrength: 0.5,      // a stage is active when one of its features reaches this strength
  },

  // A signal keeps counting for a while after the day it fired: 79% the next day, 20% a week
  // later, gone after two weeks. Each feature keeps only its strongest decayed value, so one
  // sustained anomaly counts once, while different signals on different days add up.
  accumulation: {
    windowDays: 14,
    halfLifeDays: 3,
  },

  hr: {
    maxBoost: 1,             // the amplifier H is between 1 and 2
    departure: { weight: 0.6, fullWithinDays: 30, rampFromDays: 90 },
    negativeReview: { weight: 0.3, halfLifeDays: 45, maxAgeDays: 180 },
    disciplinary: { weight: 0.35, halfLifeDays: 45, maxAgeDays: 180 },
    compensationCut: { weight: 0.2, halfLifeDays: 45, maxAgeDays: 180 },
    managerChange: { weight: 0.1, halfLifeDays: 30, maxAgeDays: 90 },
    ptoDump: { weight: 0.25, halfLifeDays: 30, maxAgeDays: 90, minShareOfBalance: 0.8, minDays: 5 },
    nonEmployee: 0.1,
    newHire: { weight: 0.05, withinDays: 90 },
    // Used when only the snapshot's HR flags are available, not a dated HR timeline.
    flagBoosts: {
      recent_negative_review_flag: 0.3,
      recent_disciplinary_action_flag: 0.35,
      pto_dump_flag: 0.25,
      manager_change_flag: 0.1,
      compensation_change_flag: 0.2,
    },
  },

  // Minimum final score when a signal fires that has no innocent explanation.
  floors: {
    honeytoken: 100,
    features: { audit_log_modification_flag: 70, session_token_reuse_flag: 70 },
  },

  levels: { medium: 40, high: 70, critical: 90 },
});

// How strongly each kind of signal points at insider risk (0 to 1), before its size, the data's
// value or context. Splunk RBA calls this "confidence"; the asset term below is "impact".
const CATEGORY_WEIGHTS = deepFreeze({
  data_movement: 1,
  access_resource: 0.9,
  privilege_permission: 0.9,
  authentication_identity: 0.8,
  device_network: 0.8,
  communication_collaboration: 0.7,
  behavioral_biometrics: 0.6,
  physical_environmental: 0.6,
  temporal: 0.5,
  hr_org_context: 0,
});

const FEATURE_WEIGHTS = deepFreeze({
  // Precursors with few innocent readings.
  audit_log_modification_flag: 1,
  pre_transfer_compression_flag: 1,
  personal_cloud_transfer_flag: 1,
  usb_write_activity_count: 1,
  impossible_travel_flag: 1,
  session_token_reuse_flag: 1,
  email_auto_forward_change_flag: 1,
  no_ticket_new_system_access_flag: 1,
  credential_sharing_in_chat_flag: 0.9,
  competitor_domain_contact_count: 0.9,
  tailgating_detected_flag: 0.8,
  // Weak on their own: they vary a lot for ordinary reasons.
  app_switch_frequency: 0.3,
  open_app_window_count: 0.3,
  internal_message_volume: 0.3,
  idle_time_pattern_score: 0.3,
  meeting_attendance_change_score: 0.4,
});

// Resource sensitivity (sensitivity_level enum) on the deck's 1–5 scale, used when a resource has
// no manual criticality weight.
const SENSITIVITY_WEIGHTS = deepFreeze({ public: 1, internal: 2, confidential: 4, restricted: 5 });

// Collect → stage → exfiltrate, the sequence Purview-style detectors look for within a day.
const SEQUENCE_STAGES = deepFreeze({
  collection: [
    'files_accessed_count', 'bulk_directory_access_flag', 'confidential_resource_access_count',
    'repeated_sensitive_file_access_count', 'daily_download_volume_mb', 'download_volume_vs_baseline',
  ],
  staging: ['pre_transfer_compression_flag', 'file_rename_before_export_count', 'large_clipboard_copy_event_count'],
  exfiltration: [
    'external_upload_volume_mb', 'usb_write_activity_count', 'personal_cloud_transfer_flag',
    'external_share_link_count', 'external_email_attachment_frequency', 'print_job_volume',
  ],
});

const SHADOW_AI_FEATURES = Object.freeze(['large_clipboard_copy_event_count', 'unauthorized_app_usage_flag']);

module.exports = {
  MODEL_VERSION, PARAMS, CATEGORY_WEIGHTS, FEATURE_WEIGHTS, SENSITIVITY_WEIGHTS, SEQUENCE_STAGES,
  SHADOW_AI_FEATURES, deepFreeze,
};
