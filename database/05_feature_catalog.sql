-- =========================================================
-- CrimGuard — 05: Feature catalog (data dictionary for all 100 variables)
-- One row per risk variable. The detection/scoring jobs iterate this
-- table instead of hard-coding columns, and baselines/anomalies FK to it.
--
--   signal_role         indicator  = behavioural signal scored for anomalies
--                       amplifier  = HR/org stressor that multiplies risk
--                       mitigator  = context that can explain a spike
--   anomaly_direction   which tail of the z-score is suspicious
--   context_explainable TRUE if an active ticket / project / role change
--                       may legitimately explain a spike (Case A).
--                       FALSE = never discounted (e.g. impossible travel).
--   default_z_threshold 2.6 for exfiltration-adjacent categories, 3.0
--                       elsewhere; NULL for flags / dates / categories.
-- =========================================================

CREATE TABLE feature_catalog (
    feature_key          TEXT PRIMARY KEY,
    category             feature_category NOT NULL,
    ordinal              SMALLINT NOT NULL CHECK (ordinal BETWEEN 1 AND 99),
    value_type           feature_value_type NOT NULL,
    unit                 TEXT,
    signal_role          TEXT NOT NULL DEFAULT 'indicator'
                         CHECK (signal_role IN ('indicator', 'amplifier', 'mitigator')),
    anomaly_direction    TEXT NOT NULL DEFAULT 'high'
                         CHECK (anomaly_direction IN ('high', 'low', 'both')),
    context_explainable  BOOLEAN NOT NULL,
    data_source          TEXT NOT NULL,
    source_table         TEXT,
    default_weight       NUMERIC(5,2) NOT NULL DEFAULT 1.00 CHECK (default_weight >= 0),
    default_z_threshold  NUMERIC(4,2) CHECK (default_z_threshold > 0),
    description          TEXT NOT NULL,
    UNIQUE (category, ordinal)
);

-- Per-tenant tuning of weights / thresholds; falls back to the catalog.
CREATE TABLE org_feature_settings (
    org_id        BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    feature_key   TEXT NOT NULL REFERENCES feature_catalog(feature_key) ON DELETE CASCADE,
    is_enabled    BOOLEAN NOT NULL DEFAULT true,
    weight        NUMERIC(5,2) CHECK (weight >= 0),
    z_threshold   NUMERIC(4,2) CHECK (z_threshold > 0),
    updated_by    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, feature_key)
);

INSERT INTO feature_catalog
    (feature_key, category, ordinal, value_type, unit, signal_role, anomaly_direction,
     context_explainable, data_source, source_table, default_z_threshold, description)
VALUES
-- ===== 1. ACCESS & RESOURCE PATTERNS =====
('files_accessed_count',                 'access_resource', 1, 'count', 'files', 'indicator', 'high', true,  'endpoint_agent', 'file_access_events', 2.6, 'Distinct files accessed in the period'),
('distinct_resource_types_touched',      'access_resource', 2, 'count', 'types', 'indicator', 'high', true,  'endpoint_agent', 'file_access_events', 2.6, 'Number of different resource types (DB, repo, share, SaaS) touched'),
('read_write_delete_ratio',              'access_resource', 3, 'ratio', NULL,    'indicator', 'high', true,  'derived',        'file_access_events', 2.6, '(writes + deletes) / reads; high values suggest destructive or staging behaviour'),
('out_of_scope_resource_access_count',   'access_resource', 4, 'count', 'events','indicator', 'high', true,  'derived',        'file_access_events', 2.6, 'Accesses to resources outside role entitlements and assigned ticket scope'),
('first_time_resource_access_flag',      'access_resource', 5, 'flag',  NULL,    'indicator', 'high', true,  'derived',        'file_access_events', NULL, 'User touched a resource never accessed before'),
('repeated_sensitive_file_access_count', 'access_resource', 6, 'count', 'events','indicator', 'high', true,  'endpoint_agent', 'file_access_events', 2.6, 'Repeated opens of the same confidential/restricted file'),
('bulk_directory_access_flag',           'access_resource', 7, 'flag',  NULL,    'indicator', 'high', true,  'endpoint_agent', 'file_access_events', NULL, 'Whole-directory enumeration or bulk copy detected'),
('confidential_resource_access_count',   'access_resource', 8, 'count', 'events','indicator', 'high', true,  'endpoint_agent', 'file_access_events', 2.6, 'Accesses to confidential or restricted resources'),
('unusual_search_query_count',           'access_resource', 9, 'count', 'queries','indicator','high', true,  'endpoint_agent', 'file_access_events', 2.6, 'Searches for terms outside the user''s normal vocabulary (e.g. "salary", "passwords")'),
('download_volume_vs_baseline',          'access_resource',10, 'ratio', 'x',     'indicator', 'high', true,  'derived',        'data_transfer_events', 2.6, 'Download volume divided by the user''s baseline'),

-- ===== 2. TEMPORAL SIGNALS =====
('access_time_deviation_from_normal_hours','temporal', 1, 'score',   'hours', 'indicator', 'high', true,  'derived', 'file_access_events', 3.0, 'Distance of activity from the user''s normal working hours'),
('weekend_holiday_access_flag',          'temporal', 2, 'flag',    NULL,     'indicator', 'high', true,  'derived', 'org_holidays',       NULL, 'Activity on a weekend or org holiday'),
('session_duration_vs_baseline',         'temporal', 3, 'ratio',   'x',      'indicator', 'both', true,  'idp_okta','user_sessions',      3.0, 'Session length divided by the user''s baseline'),
('time_to_first_sensitive_access_sec',   'temporal', 4, 'seconds', 's',      'indicator', 'low',  true,  'derived', 'file_access_events', 3.0, 'Seconds from login to first sensitive-resource access (fast = targeted)'),
('after_hours_access_frequency',         'temporal', 5, 'ratio',   NULL,     'indicator', 'high', true,  'derived', 'file_access_events', 3.0, 'Share of events outside org working hours'),
('activity_start_end_time_shift',        'temporal', 6, 'score',   'hours',  'indicator', 'both', true,  'derived', 'user_sessions',      3.0, 'Shift of first/last activity time versus baseline'),
('leave_period_activity_flag',           'temporal', 7, 'flag',    NULL,     'indicator', 'high', false, 'workday', 'leave_periods',      NULL, 'Activity while the user is on approved leave'),
('unusual_inactivity_gap_flag',          'temporal', 8, 'flag',    NULL,     'indicator', 'high', true,  'derived', 'user_sessions',      NULL, 'Unexplained long gap followed by activity'),
('burst_activity_flag',                  'temporal', 9, 'flag',    NULL,     'indicator', 'high', true,  'derived', 'file_access_events', NULL, 'Short window with abnormally dense activity'),
('day_of_week_pattern_change_score',     'temporal',10, 'score',   NULL,     'indicator', 'high', true,  'derived', 'user_sessions',      3.0, 'Divergence of weekday activity distribution from baseline'),

-- ===== 3. DATA MOVEMENT & EXFILTRATION =====
('daily_download_volume_mb',             'data_movement', 1, 'volume_mb', 'MB',     'indicator', 'high', true,  'endpoint_agent', 'data_transfer_events', 2.6, 'Total MB downloaded'),
('external_upload_volume_mb',            'data_movement', 2, 'volume_mb', 'MB',     'indicator', 'high', true,  'dlp_proxy',      'data_transfer_events', 2.6, 'Total MB uploaded to external destinations (incl. GenAI tools)'),
('external_email_attachment_frequency',  'data_movement', 3, 'ratio',     'per day','indicator', 'high', true,  'email_chat',     'communication_events', 2.6, 'Attachments sent to external recipients'),
('usb_write_activity_count',             'data_movement', 4, 'count',     'events', 'indicator', 'high', false, 'endpoint_agent', 'data_transfer_events', 2.6, 'Writes to removable media'),
('print_job_volume',                     'data_movement', 5, 'count',     'pages',  'indicator', 'high', true,  'endpoint_agent', 'data_transfer_events', 2.6, 'Printed pages'),
('large_clipboard_copy_event_count',     'data_movement', 6, 'count',     'events', 'indicator', 'high', false, 'endpoint_agent', 'clipboard_events',     2.6, 'Clipboard copies above size threshold (Shadow AI paste bursts)'),
('pre_transfer_compression_flag',        'data_movement', 7, 'flag',      NULL,     'indicator', 'high', false, 'endpoint_agent', 'data_transfer_events', NULL, 'Files archived/compressed shortly before transfer'),
('file_rename_before_export_count',      'data_movement', 8, 'count',     'files',  'indicator', 'high', false, 'endpoint_agent', 'file_access_events',   2.6, 'Files renamed (often to disguise) before leaving'),
('personal_cloud_transfer_flag',         'data_movement', 9, 'flag',      NULL,     'indicator', 'high', false, 'dlp_proxy',      'data_transfer_events', NULL, 'Transfer to personal cloud storage'),
('external_share_link_count',            'data_movement',10, 'count',     'links',  'indicator', 'high', true,  'saas_audit',     'data_transfer_events', 2.6, 'Public / external sharing links created'),

-- ===== 4. AUTHENTICATION & IDENTITY =====
('failed_login_attempt_count',           'authentication_identity', 1, 'count', 'attempts','indicator', 'high', false, 'idp_okta', 'auth_events',   3.0, 'Failed logins'),
('new_device_login_flag',                'authentication_identity', 2, 'flag',  NULL,      'indicator', 'high', true,  'idp_okta', 'auth_events',   NULL, 'Login from a never-seen device'),
('new_geolocation_login_flag',           'authentication_identity', 3, 'flag',  NULL,      'indicator', 'high', true,  'idp_okta', 'auth_events',   NULL, 'Login from a never-seen city/country'),
('concurrent_session_diff_location_flag','authentication_identity', 4, 'flag',  NULL,      'indicator', 'high', false, 'idp_okta', 'user_sessions', NULL, 'Simultaneous sessions from different locations'),
('mfa_bypass_dismissal_count',           'authentication_identity', 5, 'count', 'events',  'indicator', 'high', false, 'idp_okta', 'auth_events',   3.0, 'MFA prompts dismissed, bypassed or failed'),
('password_reset_frequency',             'authentication_identity', 6, 'count', 'resets',  'indicator', 'high', false, 'idp_okta', 'auth_events',   3.0, 'Password resets in the period'),
('shared_service_account_usage_flag',    'authentication_identity', 7, 'flag',  NULL,      'indicator', 'high', true,  'idp_okta', 'auth_events',   NULL, 'Human user authenticated as a shared/service account'),
('vpn_usage_anomaly_score',              'authentication_identity', 8, 'score', NULL,      'indicator', 'high', true,  'network_proxy', 'auth_events', 3.0, 'Deviation in VPN usage pattern'),
('session_token_reuse_flag',             'authentication_identity', 9, 'flag',  NULL,      'indicator', 'high', false, 'idp_okta', 'auth_events',   NULL, 'Session token replayed from another context (hijack indicator)'),
('privilege_escalation_request_count',   'authentication_identity',10, 'count', 'requests','indicator', 'high', true,  'idp_okta', 'auth_events',   3.0, 'Requests for elevated privileges'),

-- ===== 5. DEVICE & NETWORK =====
('new_device_fingerprint_flag',          'device_network', 1, 'flag',  NULL,     'indicator', 'high', true,  'endpoint_agent', 'devices',          NULL, 'Unseen device fingerprint for this user'),
('unmanaged_device_access_flag',         'device_network', 2, 'flag',  NULL,     'indicator', 'high', false, 'endpoint_agent', 'devices',          NULL, 'Access from a device not enrolled in MDM'),
('personal_device_sensitive_access_flag','device_network', 3, 'flag',  NULL,     'indicator', 'high', false, 'endpoint_agent', 'devices',          NULL, 'Sensitive resource accessed from a BYOD device'),
('unusual_ip_range_flag',                'device_network', 4, 'flag',  NULL,     'indicator', 'high', true,  'network_proxy',  'network_events',   NULL, 'Source IP outside usual ranges / ASNs'),
('impossible_travel_flag',               'device_network', 5, 'flag',  NULL,     'indicator', 'high', false, 'idp_okta',       'auth_events',      NULL, 'Two logins too far apart to travel between in the elapsed time'),
('user_agent_inconsistency_flag',        'device_network', 6, 'flag',  NULL,     'indicator', 'high', false, 'idp_okta',       'auth_events',      NULL, 'User agent does not match the device fingerprint'),
('bandwidth_usage_spike',                'device_network', 7, 'ratio', 'x',      'indicator', 'high', true,  'network_proxy',  'network_events',   3.0, 'Outbound bandwidth divided by baseline'),
('suspicious_dns_request_count',         'device_network', 8, 'count', 'queries','indicator', 'high', false, 'network_proxy',  'network_events',   3.0, 'DNS queries to DGA / tunneling / low-reputation domains'),
('unauthorized_app_usage_flag',          'device_network', 9, 'flag',  NULL,     'indicator', 'high', false, 'endpoint_agent', 'endpoint_events',  NULL, 'Unsanctioned application (incl. unapproved GenAI) used'),
('edr_alert_correlation_count',          'device_network',10, 'count', 'alerts', 'indicator', 'high', false, 'edr',            'edr_alerts',       3.0, 'EDR alerts on the user''s devices in the period'),

-- ===== 6. BEHAVIORAL BIOMETRICS =====
('keystroke_cadence_deviation',          'behavioral_biometrics', 1, 'score', 'sigma',  'indicator', 'high', false, 'endpoint_agent', 'biometric_samples', 3.0, 'Typing rhythm deviation from the user profile'),
('mouse_velocity_deviation',             'behavioral_biometrics', 2, 'score', 'sigma',  'indicator', 'high', false, 'endpoint_agent', 'biometric_samples', 3.0, 'Mouse velocity deviation from the user profile'),
('scroll_behavior_consistency_score',    'behavioral_biometrics', 3, 'score', NULL,     'indicator', 'low',  false, 'endpoint_agent', 'biometric_samples', 3.0, 'Similarity of scroll behaviour to profile (low = someone else?)'),
('app_switch_frequency',                 'behavioral_biometrics', 4, 'count', 'switches','indicator','both', true,  'endpoint_agent', 'biometric_samples', 3.0, 'Application focus switches'),
('idle_time_pattern_score',              'behavioral_biometrics', 5, 'score', NULL,     'indicator', 'high', true,  'endpoint_agent', 'biometric_samples', 3.0, 'Deviation of idle-time pattern from baseline'),
('cli_terminal_usage_frequency',         'behavioral_biometrics', 6, 'count', 'commands','indicator','high', true,  'endpoint_agent', 'endpoint_events',   3.0, 'Terminal / shell commands executed'),
('copy_paste_frequency_volume',          'behavioral_biometrics', 7, 'count', 'events', 'indicator', 'high', true,  'endpoint_agent', 'clipboard_events',  3.0, 'Copy/paste operations'),
('screenshot_recording_activity_count',  'behavioral_biometrics', 8, 'count', 'events', 'indicator', 'high', false, 'endpoint_agent', 'endpoint_events',   3.0, 'Screenshots and screen recordings'),
('open_app_window_count',                'behavioral_biometrics', 9, 'count', 'windows','indicator', 'both', true,  'endpoint_agent', 'biometric_samples', 3.0, 'Concurrently open windows'),
('digital_signature_deviation_score',    'behavioral_biometrics',10, 'score', 'sigma',  'indicator', 'high', false, 'endpoint_agent', 'biometric_samples', 3.0, 'Composite behavioural-signature deviation'),

-- ===== 7. HR & ORGANIZATIONAL CONTEXT =====
('recent_role_change_flag',              'hr_org_context', 1, 'flag',     NULL,     'mitigator', 'high', false, 'workday', 'user_role_assignments', NULL, 'Role changed recently (explains new access patterns)'),
('termination_date_on_file',             'hr_org_context', 2, 'date',     NULL,     'amplifier', 'high', false, 'workday', 'users',                 NULL, 'Scheduled termination / resignation date, if any'),
('recent_negative_review_flag',          'hr_org_context', 3, 'flag',     NULL,     'amplifier', 'high', false, 'workday', 'hr_events',             NULL, 'Recent poor performance review or PIP'),
('pto_dump_flag',                        'hr_org_context', 4, 'flag',     NULL,     'amplifier', 'high', false, 'workday', 'leave_periods',         NULL, 'Large share of remaining PTO booked at once (pre-departure signal)'),
('recent_disciplinary_action_flag',      'hr_org_context', 5, 'flag',     NULL,     'amplifier', 'high', false, 'workday', 'hr_events',             NULL, 'Recent disciplinary action'),
('tenure_months',                        'hr_org_context', 6, 'months',   'months', 'amplifier', 'low',  false, 'workday', 'users',                 NULL, 'Months since hire'),
('recent_project_assignment_flag',       'hr_org_context', 7, 'flag',     NULL,     'mitigator', 'high', false, 'jira',    'ticket_assignments',    NULL, 'Newly assigned project/ticket (explains spikes, Case A)'),
('manager_change_flag',                  'hr_org_context', 8, 'flag',     NULL,     'amplifier', 'high', false, 'workday', 'hr_events',             NULL, 'Reporting manager changed recently'),
('compensation_change_flag',             'hr_org_context', 9, 'flag',     NULL,     'amplifier', 'high', false, 'workday', 'hr_events',             NULL, 'Compensation changed recently (esp. negative)'),
('employment_type',                      'hr_org_context',10, 'category', NULL,     'amplifier', 'both', false, 'workday', 'users',                 NULL, 'full_time | contractor | temp'),

-- ===== 8. COMMUNICATION & COLLABORATION =====
('internal_message_volume',              'communication_collaboration', 1, 'count', 'messages', 'indicator', 'both', true,  'email_chat', 'communication_events', 3.0, 'Internal messages sent'),
('external_message_increase_score',      'communication_collaboration', 2, 'score', NULL,       'indicator', 'high', true,  'email_chat', 'communication_events', 3.0, 'Growth of external messaging vs baseline'),
('email_auto_forward_change_flag',       'communication_collaboration', 3, 'flag',  NULL,       'indicator', 'high', false, 'email_chat', 'communication_events', NULL, 'Auto-forward rule created or changed'),
('sensitive_keyword_message_count',      'communication_collaboration', 4, 'count', 'messages', 'indicator', 'high', true,  'email_chat', 'communication_events', 3.0, 'Messages matching sensitive keyword dictionaries'),
('credential_sharing_in_chat_flag',      'communication_collaboration', 5, 'flag',  NULL,       'indicator', 'high', false, 'email_chat', 'communication_events', NULL, 'Password / secret pattern posted in chat'),
('meeting_attendance_change_score',      'communication_collaboration', 6, 'score', NULL,       'indicator', 'high', true,  'email_chat', 'communication_events', 3.0, 'Change in meeting attendance (disengagement)'),
('ephemeral_app_usage_flag',             'communication_collaboration', 7, 'flag',  NULL,       'indicator', 'high', false, 'dlp_proxy',  'communication_events', NULL, 'Use of disappearing-message apps'),
('calendar_activity_anomaly_flag',       'communication_collaboration', 8, 'flag',  NULL,       'indicator', 'high', true,  'email_chat', 'communication_events', NULL, 'Unusual calendar pattern (e.g. many "personal" blocks, interviews)'),
('new_external_contact_growth_rate',     'communication_collaboration', 9, 'ratio', NULL,       'indicator', 'high', true,  'email_chat', 'communication_events', 3.0, 'Rate of new external correspondents'),
('competitor_domain_contact_count',      'communication_collaboration',10, 'count', 'messages', 'indicator', 'high', false, 'email_chat', 'communication_events', 3.0, 'Messages to/from known competitor domains'),

-- ===== 9. PRIVILEGE & PERMISSION =====
('permission_change_count',              'privilege_permission', 1, 'count', 'changes', 'indicator', 'high', true,  'saas_audit', 'privilege_events', 3.0, 'Permission changes performed'),
('admin_panel_access_flag',              'privilege_permission', 2, 'flag',  NULL,      'indicator', 'high', true,  'saas_audit', 'privilege_events', NULL, 'Admin console accessed'),
('new_account_creation_count',           'privilege_permission', 3, 'count', 'accounts','indicator', 'high', true,  'idp_okta',   'privilege_events', 3.0, 'Accounts created'),
('audit_log_modification_flag',          'privilege_permission', 4, 'flag',  NULL,      'indicator', 'high', false, 'saas_audit', 'privilege_events', NULL, 'Audit logs modified or deleted (anti-forensics)'),
('break_glass_account_usage_flag',       'privilege_permission', 5, 'flag',  NULL,      'indicator', 'high', true,  'idp_okta',   'privilege_events', NULL, 'Emergency break-glass account used'),
('least_privilege_violation_flag',       'privilege_permission', 6, 'flag',  NULL,      'indicator', 'high', false, 'derived',    'privilege_events', NULL, 'Holds or uses rights beyond role entitlements'),
('sensitive_group_membership_change_flag','privilege_permission',7, 'flag',  NULL,      'indicator', 'high', true,  'idp_okta',   'privilege_events', NULL, 'Added to / removed from a sensitive group'),
('api_key_generation_frequency',         'privilege_permission', 8, 'count', 'keys',    'indicator', 'high', true,  'saas_audit', 'privilege_events', 3.0, 'API keys / tokens generated'),
('firewall_rule_change_count',           'privilege_permission', 9, 'count', 'changes', 'indicator', 'high', true,  'saas_audit', 'privilege_events', 3.0, 'Firewall / security-group rule changes'),
('no_ticket_new_system_access_flag',     'privilege_permission',10, 'flag',  NULL,      'indicator', 'high', false, 'derived',    'privilege_events', NULL, 'Access to a new system granted with no backing ticket'),

-- ===== 10. PHYSICAL & ENVIRONMENTAL =====
('badge_restricted_area_access_count',   'physical_environmental', 1, 'count', 'entries', 'indicator', 'high', true,  'badge_system', 'physical_access_events', 3.0, 'Badge entries into restricted zones'),
('after_hours_building_entry_flag',      'physical_environmental', 2, 'flag',  NULL,      'indicator', 'high', true,  'badge_system', 'physical_access_events', NULL, 'Building entry outside working hours'),
('badge_digital_location_mismatch_flag', 'physical_environmental', 3, 'flag',  NULL,      'indicator', 'high', false, 'derived',      'physical_access_events', NULL, 'Badge location contradicts login location'),
('tailgating_detected_flag',             'physical_environmental', 4, 'flag',  NULL,      'indicator', 'high', false, 'badge_system', 'physical_access_events', NULL, 'Entry without badge swipe detected'),
('server_room_access_out_of_role_flag',  'physical_environmental', 5, 'flag',  NULL,      'indicator', 'high', true,  'badge_system', 'physical_access_events', NULL, 'Server-room entry by a role not in zone_role_access'),
('offhours_parking_entry_correlation_flag','physical_environmental',6,'flag',  NULL,      'indicator', 'high', true,  'badge_system', 'physical_access_events', NULL, 'Off-hours parking entry correlated with digital activity'),
('multiple_restricted_door_attempts_count','physical_environmental',7,'count', 'attempts','indicator', 'high', false, 'badge_system', 'physical_access_events', 3.0, 'Denied badge attempts on restricted doors'),
('visitor_sponsor_frequency_anomaly_flag','physical_environmental', 8, 'flag',  NULL,      'indicator', 'high', true,  'badge_system', 'physical_access_events', NULL, 'Unusual number of visitors sponsored'),
('asset_checkout_count',                 'physical_environmental', 9, 'count', 'assets',  'indicator', 'high', true,  'badge_system', 'physical_access_events', 3.0, 'Hardware / media assets checked out'),
('sensitive_document_print_copy_count',  'physical_environmental',10, 'count', 'documents','indicator','high', false, 'endpoint_agent','physical_access_events', 3.0, 'Sensitive documents printed or photocopied');
