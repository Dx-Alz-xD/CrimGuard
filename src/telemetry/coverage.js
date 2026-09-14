'use strict';

// How the Red website collects each of the 100 risk variables in
// database/crimguard/05_feature_catalog.sql. One entry per feature_key, and the module
// refuses to load if the two ever drift apart.
//
//   measured   the browser or the server observes it directly
//   derived    computed from measured events or from what Red already stores
//   no-source  needs a system Red isn't connected to (badge readers, EDR, MDM, a mail
//              gateway, a DLP proxy, an IdP with MFA). Written as NULL, which
//              06_feature_snapshots.sql defines as "not collected" - never as 0 or false.
//
// `note` is shown in the risk console next to the value, so an analyst can always see
// where a number came from and why a blank is blank.

const MEASURED = 'measured';
const DERIVED = 'derived';
const NO_SOURCE = 'no-source';

const COVERAGE = {
  // ===== 1. ACCESS & RESOURCE PATTERNS =====
  files_accessed_count: [MEASURED, 'Distinct projects, pages and admin records opened.'],
  distinct_resource_types_touched: [MEASURED, 'How many kinds of resource (project, page, account record) were touched.'],
  read_write_delete_ratio: [DERIVED, 'Writes and deletes over reads, across every resource.'],
  out_of_scope_resource_access_count: [DERIVED, "Requests for resources the account's role is not entitled to."],
  first_time_resource_access_flag: [DERIVED, 'A resource this account had never opened before.'],
  repeated_sensitive_file_access_count: [DERIVED, 'Repeat opens of the same confidential resource.'],
  bulk_directory_access_flag: [DERIVED, 'Whole-list enumeration: many distinct resources in one short burst.'],
  confidential_resource_access_count: [DERIVED, 'Opens of resources classified confidential or restricted.'],
  unusual_search_query_count: [MEASURED, 'Searches matching the sensitive-term dictionary.'],
  download_volume_vs_baseline: [DERIVED, "Bytes exported today over the account's own 30-day median."],

  // ===== 2. TEMPORAL SIGNALS =====
  access_time_deviation_from_normal_hours: [DERIVED, "Hours between today's median activity time and the account's usual one."],
  weekend_holiday_access_flag: [DERIVED, 'Activity on a Saturday, Sunday or a date in org_holidays.'],
  session_duration_vs_baseline: [DERIVED, "Signed-in seconds today over the account's own median."],
  time_to_first_sensitive_access_sec: [DERIVED, 'Seconds from sign-in to the first confidential resource.'],
  after_hours_access_frequency: [DERIVED, "Share of events outside the organisation's working hours."],
  activity_start_end_time_shift: [DERIVED, 'Shift in first and last activity of the day, in hours, signed.'],
  leave_period_activity_flag: [DERIVED, 'Activity during an approved leave period on file.'],
  unusual_inactivity_gap_flag: [DERIVED, 'Activity returning after a gap much longer than usual.'],
  burst_activity_flag: [DERIVED, 'A five-minute window holding an outsized share of the day.'],
  day_of_week_pattern_change_score: [DERIVED, 'Divergence of the weekday activity mix from the 90-day pattern.'],

  // ===== 3. DATA MOVEMENT & EXFILTRATION =====
  daily_download_volume_mb: [MEASURED, 'Bytes leaving through project exports.'],
  external_upload_volume_mb: [NO_SOURCE, 'Needs a DLP proxy: a page cannot see uploads to other sites.'],
  external_email_attachment_frequency: [NO_SOURCE, 'Needs the mail gateway. Red sends no mail.'],
  usb_write_activity_count: [NO_SOURCE, 'Needs an endpoint agent: a browser cannot see removable media.'],
  print_job_volume: [MEASURED, 'Print dialogs opened from a Red page.'],
  large_clipboard_copy_event_count: [MEASURED, 'Copies above the large-copy threshold. Length only, never content.'],
  pre_transfer_compression_flag: [NO_SOURCE, 'Needs an endpoint agent to see archiving before a transfer.'],
  file_rename_before_export_count: [DERIVED, 'Projects renamed shortly before being exported.'],
  personal_cloud_transfer_flag: [NO_SOURCE, 'Needs a DLP proxy to classify the destination.'],
  external_share_link_count: [NO_SOURCE, 'Red has no sharing links to count.'],

  // ===== 4. AUTHENTICATION & IDENTITY =====
  failed_login_attempt_count: [MEASURED, 'Rejected sign-ins for this account.'],
  new_device_login_flag: [DERIVED, 'Sign-in from a device fingerprint never seen for this account.'],
  new_geolocation_login_flag: [DERIVED, 'Sign-in from a network, time zone or country this account has not used before.'],
  concurrent_session_diff_location_flag: [DERIVED, 'Sessions open at the same time from different networks.'],
  mfa_bypass_dismissal_count: [NO_SOURCE, 'Red has no second factor to dismiss.'],
  password_reset_frequency: [MEASURED, 'Password changes and admin resets on this account.'],
  shared_service_account_usage_flag: [NO_SOURCE, 'Red has no service accounts.'],
  vpn_usage_anomaly_score: [NO_SOURCE, 'Needs the network proxy to tell a VPN from any other address.'],
  session_token_reuse_flag: [MEASURED, 'A session cookie presented after that session ended.'],
  privilege_escalation_request_count: [NO_SOURCE, 'Red has no request-for-access flow; admins grant roles directly.'],

  // ===== 5. DEVICE & NETWORK =====
  new_device_fingerprint_flag: [DERIVED, 'An unseen browser and hardware fingerprint for this account.'],
  unmanaged_device_access_flag: [NO_SOURCE, 'Needs MDM enrolment data. A page cannot tell a managed device from a personal one.'],
  personal_device_sensitive_access_flag: [NO_SOURCE, 'Needs MDM enrolment data, as above.'],
  unusual_ip_range_flag: [DERIVED, "Any address this account was seen from today that is outside its usual ones, including a network it moved to mid-session."],
  impossible_travel_flag: [DERIVED, 'Two sign-ins from different networks, further apart than the time between them allows: over 900 km/h implied.'],
  user_agent_inconsistency_flag: [DERIVED, 'The user agent contradicts the platform the fingerprint reports.'],
  bandwidth_usage_spike: [DERIVED, "Response bytes served today over this account's median."],
  suspicious_dns_request_count: [NO_SOURCE, 'Needs the resolver or network proxy.'],
  unauthorized_app_usage_flag: [NO_SOURCE, 'Needs an endpoint agent: a page cannot see other applications.'],
  edr_alert_correlation_count: [NO_SOURCE, 'Needs an EDR feed.'],

  // ===== 6. BEHAVIORAL BIOMETRICS =====
  // Timing statistics only. Key identities and clipboard contents are never sent or stored.
  keystroke_cadence_deviation: [DERIVED, "Typing rhythm today against this account's own profile, in sigma."],
  mouse_velocity_deviation: [DERIVED, "Pointer speed today against this account's own profile, in sigma."],
  scroll_behavior_consistency_score: [DERIVED, 'How closely scrolling matches the usual profile, 0 to 1.'],
  app_switch_frequency: [MEASURED, 'Times the Red tab lost and regained focus.'],
  idle_time_pattern_score: [DERIVED, 'Deviation of the idle-time pattern from the usual one.'],
  cli_terminal_usage_frequency: [NO_SOURCE, 'Needs an endpoint agent. There is no terminal in a browser.'],
  copy_paste_frequency_volume: [MEASURED, 'Copy, cut and paste actions on Red pages.'],
  screenshot_recording_activity_count: [MEASURED, 'Print Screen presses and screen-capture starts, where the browser reports them.'],
  open_app_window_count: [MEASURED, 'Red tabs this account had open at once.'],
  digital_signature_deviation_score: [DERIVED, 'Combined keystroke, pointer, scroll and idle deviation.'],

  // ===== 7. HR & ORGANIZATIONAL CONTEXT =====
  // Kept in the CrimGuard tables and edited by admins under People, since Red has no HR system.
  recent_role_change_flag: [MEASURED, 'The role on this account was changed in Red in the last 30 days.'],
  termination_date_on_file: [MEASURED, 'Leaving date recorded for this account.'],
  recent_negative_review_flag: [MEASURED, 'A negative review recorded in the last 180 days.'],
  pto_dump_flag: [DERIVED, 'A leave request taking most of the remaining balance at once.'],
  recent_disciplinary_action_flag: [MEASURED, 'A disciplinary action recorded in the last 180 days.'],
  tenure_months: [DERIVED, 'Months since the hire date, or since the account was created.'],
  recent_project_assignment_flag: [DERIVED, 'A project started or joined in the last 30 days.'],
  manager_change_flag: [MEASURED, 'A manager change recorded in the last 90 days.'],
  compensation_change_flag: [MEASURED, 'A compensation change recorded in the last 90 days.'],
  employment_type: [MEASURED, 'Employment type recorded for this account.'],

  // ===== 8. COMMUNICATION & COLLABORATION =====
  internal_message_volume: [NO_SOURCE, 'Red has no messaging.'],
  external_message_increase_score: [NO_SOURCE, 'Red has no messaging.'],
  email_auto_forward_change_flag: [NO_SOURCE, 'Needs the mail system.'],
  sensitive_keyword_message_count: [DERIVED, 'Project text written today that matches the sensitive-term dictionary.'],
  credential_sharing_in_chat_flag: [DERIVED, 'A password, key or token pattern written into project text.'],
  meeting_attendance_change_score: [NO_SOURCE, 'Needs a calendar.'],
  ephemeral_app_usage_flag: [NO_SOURCE, 'Needs a DLP proxy.'],
  calendar_activity_anomaly_flag: [NO_SOURCE, 'Needs a calendar.'],
  new_external_contact_growth_rate: [NO_SOURCE, 'Red has no correspondents.'],
  competitor_domain_contact_count: [NO_SOURCE, 'Needs the mail system.'],

  // ===== 9. PRIVILEGE & PERMISSION =====
  permission_change_count: [MEASURED, 'Role changes this account performed on others.'],
  admin_panel_access_flag: [MEASURED, 'The admin console was opened.'],
  new_account_creation_count: [MEASURED, 'Accounts this account created.'],
  audit_log_modification_flag: [DERIVED, 'The security log lost entries outside the scheduled 12-month purge.'],
  break_glass_account_usage_flag: [NO_SOURCE, 'Red has no break-glass account.'],
  least_privilege_violation_flag: [DERIVED, 'An admin-only endpoint was called by an account without the role.'],
  sensitive_group_membership_change_flag: [MEASURED, 'Someone was promoted to, or demoted from, admin.'],
  api_key_generation_frequency: [NO_SOURCE, 'Red issues no API keys.'],
  firewall_rule_change_count: [NO_SOURCE, 'Red manages no network rules.'],
  no_ticket_new_system_access_flag: [DERIVED, 'A role was granted with no ticket or project in the ledger to justify it.'],

  // ===== 10. PHYSICAL & ENVIRONMENTAL =====
  badge_restricted_area_access_count: [NO_SOURCE, 'Needs the badge system.'],
  after_hours_building_entry_flag: [NO_SOURCE, 'Needs the badge system.'],
  badge_digital_location_mismatch_flag: [NO_SOURCE, 'Needs the badge system.'],
  tailgating_detected_flag: [NO_SOURCE, 'Needs the badge system.'],
  server_room_access_out_of_role_flag: [NO_SOURCE, 'Needs the badge system.'],
  offhours_parking_entry_correlation_flag: [NO_SOURCE, 'Needs the badge system.'],
  multiple_restricted_door_attempts_count: [NO_SOURCE, 'Needs the badge system.'],
  visitor_sponsor_frequency_anomaly_flag: [NO_SOURCE, 'Needs the badge system.'],
  asset_checkout_count: [NO_SOURCE, 'Needs the asset register.'],
  sensitive_document_print_copy_count: [DERIVED, 'Pages printed while a confidential resource was open.'],
};

const coverage = Object.fromEntries(
  Object.entries(COVERAGE).map(([key, [collection, note]]) => [key, { key, collection, note }]),
);

const isCollected = (key) => coverage[key] !== undefined && coverage[key].collection !== NO_SOURCE;

// Every key the pipeline actually fills in. Anything else is deliberately left NULL.
const collectedKeys = () => Object.keys(coverage).filter(isCollected);

// Throws if coverage and the catalog have drifted apart, so a new variable can't be added to
// the catalog without deciding how - or whether - the website collects it.
function assertCoversCatalog(catalogKeys) {
  const missing = catalogKeys.filter((key) => !coverage[key]);
  const extra = Object.keys(coverage).filter((key) => !catalogKeys.includes(key));
  if (missing.length || extra.length) {
    throw new Error(
      `src/telemetry/coverage.js is out of step with the feature catalog.${
        missing.length ? ` Not covered: ${missing.join(', ')}.` : ''
      }${extra.length ? ` Unknown here: ${extra.join(', ')}.` : ''}`,
    );
  }
}

function summary() {
  const counts = { [MEASURED]: 0, [DERIVED]: 0, [NO_SOURCE]: 0 };
  for (const entry of Object.values(coverage)) counts[entry.collection] += 1;
  return { ...counts, total: Object.keys(coverage).length, collected: counts[MEASURED] + counts[DERIVED] };
}

module.exports = { MEASURED, DERIVED, NO_SOURCE, coverage, isCollected, collectedKeys, assertCoversCatalog, summary };
