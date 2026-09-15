-- =========================================================
-- CrimGuard — 06: Risk feature snapshots (the 100 variables)
-- One snapshot per user per period (day by default). Supersedes the
-- single wide table the first draft used.
--
-- Split into one table per category, 1:1 with the snapshot header,
-- because each category is fed by a different source on its own
-- schedule (Workday nightly, badge system, endpoint agent...). In
-- PostgreSQL every UPDATE rewrites the whole row, so one 100-column row
-- touched by 10 writers means heavy bloat and write contention.
-- v_risk_feature_vector (bottom) flattens everything back into one row
-- for z-scores / Isolation Forest.
--
-- NULL = source not integrated / not collected for this period.
-- It is NOT the same as 0 / false; impute deliberately in the model.
-- *_deviation / *_anomaly_score / *_change_score columns are magnitudes
-- (>= 0); the few signed columns are commented inline.
-- =========================================================

CREATE TABLE risk_feature_snapshot (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    snapshot_date   DATE NOT NULL,
    period_start    TIMESTAMPTZ NOT NULL,
    period_end      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, snapshot_date),
    CHECK (period_end > period_start)
);
CREATE INDEX idx_snapshot_date ON risk_feature_snapshot (snapshot_date);
-- (user_id, snapshot_date) lookups are served by the UNIQUE index above.

-- ===== 1. ACCESS & RESOURCE PATTERNS =====
CREATE TABLE feat_access_resource (
    snapshot_id                          BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    files_accessed_count                 INTEGER CHECK (files_accessed_count >= 0),
    distinct_resource_types_touched      INTEGER CHECK (distinct_resource_types_touched >= 0),
    read_write_delete_ratio              DOUBLE PRECISION CHECK (read_write_delete_ratio >= 0),
    out_of_scope_resource_access_count   INTEGER CHECK (out_of_scope_resource_access_count >= 0),
    first_time_resource_access_flag      BOOLEAN,
    repeated_sensitive_file_access_count INTEGER CHECK (repeated_sensitive_file_access_count >= 0),
    bulk_directory_access_flag           BOOLEAN,
    confidential_resource_access_count   INTEGER CHECK (confidential_resource_access_count >= 0),
    unusual_search_query_count           INTEGER CHECK (unusual_search_query_count >= 0),
    download_volume_vs_baseline          DOUBLE PRECISION CHECK (download_volume_vs_baseline >= 0),
    computed_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 2. TEMPORAL SIGNALS =====
CREATE TABLE feat_temporal (
    snapshot_id                             BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    access_time_deviation_from_normal_hours DOUBLE PRECISION CHECK (access_time_deviation_from_normal_hours >= 0),
    weekend_holiday_access_flag             BOOLEAN,
    session_duration_vs_baseline            DOUBLE PRECISION CHECK (session_duration_vs_baseline >= 0),
    time_to_first_sensitive_access_sec      INTEGER CHECK (time_to_first_sensitive_access_sec >= 0),
    after_hours_access_frequency            DOUBLE PRECISION CHECK (after_hours_access_frequency BETWEEN 0 AND 1),
    activity_start_end_time_shift           DOUBLE PRECISION,  -- hours, signed
    leave_period_activity_flag              BOOLEAN,
    unusual_inactivity_gap_flag             BOOLEAN,
    burst_activity_flag                     BOOLEAN,
    day_of_week_pattern_change_score        DOUBLE PRECISION CHECK (day_of_week_pattern_change_score >= 0),
    computed_at                             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 3. DATA MOVEMENT & EXFILTRATION =====
CREATE TABLE feat_data_movement (
    snapshot_id                          BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    daily_download_volume_mb             DOUBLE PRECISION CHECK (daily_download_volume_mb >= 0),
    external_upload_volume_mb            DOUBLE PRECISION CHECK (external_upload_volume_mb >= 0),
    external_email_attachment_frequency  DOUBLE PRECISION CHECK (external_email_attachment_frequency >= 0),
    usb_write_activity_count             INTEGER CHECK (usb_write_activity_count >= 0),
    print_job_volume                     INTEGER CHECK (print_job_volume >= 0),
    large_clipboard_copy_event_count     INTEGER CHECK (large_clipboard_copy_event_count >= 0),
    pre_transfer_compression_flag        BOOLEAN,
    file_rename_before_export_count      INTEGER CHECK (file_rename_before_export_count >= 0),
    personal_cloud_transfer_flag         BOOLEAN,
    external_share_link_count            INTEGER CHECK (external_share_link_count >= 0),
    computed_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 4. AUTHENTICATION & IDENTITY =====
CREATE TABLE feat_authentication_identity (
    snapshot_id                          BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    failed_login_attempt_count           INTEGER CHECK (failed_login_attempt_count >= 0),
    new_device_login_flag                BOOLEAN,
    new_geolocation_login_flag           BOOLEAN,
    concurrent_session_diff_location_flag BOOLEAN,
    mfa_bypass_dismissal_count           INTEGER CHECK (mfa_bypass_dismissal_count >= 0),
    password_reset_frequency             INTEGER CHECK (password_reset_frequency >= 0),
    shared_service_account_usage_flag    BOOLEAN,
    vpn_usage_anomaly_score              DOUBLE PRECISION CHECK (vpn_usage_anomaly_score >= 0),
    session_token_reuse_flag             BOOLEAN,
    privilege_escalation_request_count   INTEGER CHECK (privilege_escalation_request_count >= 0),
    computed_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 5. DEVICE & NETWORK =====
CREATE TABLE feat_device_network (
    snapshot_id                          BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    new_device_fingerprint_flag          BOOLEAN,
    unmanaged_device_access_flag         BOOLEAN,
    personal_device_sensitive_access_flag BOOLEAN,
    unusual_ip_range_flag                BOOLEAN,
    impossible_travel_flag               BOOLEAN,
    user_agent_inconsistency_flag        BOOLEAN,
    bandwidth_usage_spike                DOUBLE PRECISION CHECK (bandwidth_usage_spike >= 0),
    suspicious_dns_request_count         INTEGER CHECK (suspicious_dns_request_count >= 0),
    unauthorized_app_usage_flag          BOOLEAN,
    edr_alert_correlation_count          INTEGER CHECK (edr_alert_correlation_count >= 0),
    computed_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 6. BEHAVIORAL BIOMETRICS =====
CREATE TABLE feat_behavioral_biometrics (
    snapshot_id                          BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    keystroke_cadence_deviation          DOUBLE PRECISION CHECK (keystroke_cadence_deviation >= 0),
    mouse_velocity_deviation             DOUBLE PRECISION CHECK (mouse_velocity_deviation >= 0),
    scroll_behavior_consistency_score    DOUBLE PRECISION CHECK (scroll_behavior_consistency_score BETWEEN 0 AND 1),
    app_switch_frequency                 INTEGER CHECK (app_switch_frequency >= 0),
    idle_time_pattern_score              DOUBLE PRECISION CHECK (idle_time_pattern_score >= 0),
    cli_terminal_usage_frequency         INTEGER CHECK (cli_terminal_usage_frequency >= 0),
    copy_paste_frequency_volume          INTEGER CHECK (copy_paste_frequency_volume >= 0),
    screenshot_recording_activity_count  INTEGER CHECK (screenshot_recording_activity_count >= 0),
    open_app_window_count                INTEGER CHECK (open_app_window_count >= 0),
    digital_signature_deviation_score    DOUBLE PRECISION CHECK (digital_signature_deviation_score >= 0),
    computed_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 7. HR & ORGANIZATIONAL CONTEXT =====
-- Point-in-time copy of HR state, so models train on what was known
-- that day rather than today's values.
CREATE TABLE feat_hr_org_context (
    snapshot_id                          BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    recent_role_change_flag              BOOLEAN,
    termination_date_on_file             DATE,
    recent_negative_review_flag          BOOLEAN,
    pto_dump_flag                        BOOLEAN,
    recent_disciplinary_action_flag      BOOLEAN,
    tenure_months                        INTEGER CHECK (tenure_months >= 0),
    recent_project_assignment_flag       BOOLEAN,
    manager_change_flag                  BOOLEAN,
    compensation_change_flag             BOOLEAN,
    employment_type                      employment_type,
    computed_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 8. COMMUNICATION & COLLABORATION =====
CREATE TABLE feat_communication_collaboration (
    snapshot_id                          BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    internal_message_volume              INTEGER CHECK (internal_message_volume >= 0),
    external_message_increase_score      DOUBLE PRECISION,  -- signed: negative = decrease
    email_auto_forward_change_flag       BOOLEAN,
    sensitive_keyword_message_count      INTEGER CHECK (sensitive_keyword_message_count >= 0),
    credential_sharing_in_chat_flag      BOOLEAN,
    meeting_attendance_change_score      DOUBLE PRECISION CHECK (meeting_attendance_change_score >= 0),
    ephemeral_app_usage_flag             BOOLEAN,
    calendar_activity_anomaly_flag       BOOLEAN,
    new_external_contact_growth_rate     DOUBLE PRECISION,  -- signed growth rate
    competitor_domain_contact_count      INTEGER CHECK (competitor_domain_contact_count >= 0),
    computed_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 9. PRIVILEGE & PERMISSION =====
CREATE TABLE feat_privilege_permission (
    snapshot_id                          BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    permission_change_count              INTEGER CHECK (permission_change_count >= 0),
    admin_panel_access_flag              BOOLEAN,
    new_account_creation_count           INTEGER CHECK (new_account_creation_count >= 0),
    audit_log_modification_flag          BOOLEAN,
    break_glass_account_usage_flag       BOOLEAN,
    least_privilege_violation_flag       BOOLEAN,
    sensitive_group_membership_change_flag BOOLEAN,
    api_key_generation_frequency         INTEGER CHECK (api_key_generation_frequency >= 0),
    firewall_rule_change_count           INTEGER CHECK (firewall_rule_change_count >= 0),
    no_ticket_new_system_access_flag     BOOLEAN,
    computed_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===== 10. PHYSICAL & ENVIRONMENTAL =====
CREATE TABLE feat_physical_environmental (
    snapshot_id                          BIGINT PRIMARY KEY REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    badge_restricted_area_access_count   INTEGER CHECK (badge_restricted_area_access_count >= 0),
    after_hours_building_entry_flag      BOOLEAN,
    badge_digital_location_mismatch_flag BOOLEAN,
    tailgating_detected_flag             BOOLEAN,
    server_room_access_out_of_role_flag  BOOLEAN,
    offhours_parking_entry_correlation_flag BOOLEAN,
    multiple_restricted_door_attempts_count INTEGER CHECK (multiple_restricted_door_attempts_count >= 0),
    visitor_sponsor_frequency_anomaly_flag BOOLEAN,
    asset_checkout_count                 INTEGER CHECK (asset_checkout_count >= 0),
    sensitive_document_print_copy_count  INTEGER CHECK (sensitive_document_print_copy_count >= 0),
    computed_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Flattened 100-variable feature vector: one row per user per day.
-- LEFT JOINs keep a snapshot even when a category source is missing.
CREATE VIEW v_risk_feature_vector AS
SELECT
    s.id AS snapshot_id, s.user_id, u.org_id, s.snapshot_date,
    -- 1. access & resource
    a.files_accessed_count, a.distinct_resource_types_touched, a.read_write_delete_ratio,
    a.out_of_scope_resource_access_count, a.first_time_resource_access_flag,
    a.repeated_sensitive_file_access_count, a.bulk_directory_access_flag,
    a.confidential_resource_access_count, a.unusual_search_query_count,
    a.download_volume_vs_baseline,
    -- 2. temporal
    t.access_time_deviation_from_normal_hours, t.weekend_holiday_access_flag,
    t.session_duration_vs_baseline, t.time_to_first_sensitive_access_sec,
    t.after_hours_access_frequency, t.activity_start_end_time_shift,
    t.leave_period_activity_flag, t.unusual_inactivity_gap_flag,
    t.burst_activity_flag, t.day_of_week_pattern_change_score,
    -- 3. data movement
    d.daily_download_volume_mb, d.external_upload_volume_mb,
    d.external_email_attachment_frequency, d.usb_write_activity_count, d.print_job_volume,
    d.large_clipboard_copy_event_count, d.pre_transfer_compression_flag,
    d.file_rename_before_export_count, d.personal_cloud_transfer_flag,
    d.external_share_link_count,
    -- 4. authentication & identity
    ai.failed_login_attempt_count, ai.new_device_login_flag, ai.new_geolocation_login_flag,
    ai.concurrent_session_diff_location_flag, ai.mfa_bypass_dismissal_count,
    ai.password_reset_frequency, ai.shared_service_account_usage_flag,
    ai.vpn_usage_anomaly_score, ai.session_token_reuse_flag,
    ai.privilege_escalation_request_count,
    -- 5. device & network
    dn.new_device_fingerprint_flag, dn.unmanaged_device_access_flag,
    dn.personal_device_sensitive_access_flag, dn.unusual_ip_range_flag,
    dn.impossible_travel_flag, dn.user_agent_inconsistency_flag, dn.bandwidth_usage_spike,
    dn.suspicious_dns_request_count, dn.unauthorized_app_usage_flag,
    dn.edr_alert_correlation_count,
    -- 6. behavioral biometrics
    b.keystroke_cadence_deviation, b.mouse_velocity_deviation,
    b.scroll_behavior_consistency_score, b.app_switch_frequency, b.idle_time_pattern_score,
    b.cli_terminal_usage_frequency, b.copy_paste_frequency_volume,
    b.screenshot_recording_activity_count, b.open_app_window_count,
    b.digital_signature_deviation_score,
    -- 7. HR & org context
    h.recent_role_change_flag, h.termination_date_on_file, h.recent_negative_review_flag,
    h.pto_dump_flag, h.recent_disciplinary_action_flag, h.tenure_months,
    h.recent_project_assignment_flag, h.manager_change_flag, h.compensation_change_flag,
    h.employment_type,
    -- 8. communication & collaboration
    c.internal_message_volume, c.external_message_increase_score,
    c.email_auto_forward_change_flag, c.sensitive_keyword_message_count,
    c.credential_sharing_in_chat_flag, c.meeting_attendance_change_score,
    c.ephemeral_app_usage_flag, c.calendar_activity_anomaly_flag,
    c.new_external_contact_growth_rate, c.competitor_domain_contact_count,
    -- 9. privilege & permission
    p.permission_change_count, p.admin_panel_access_flag, p.new_account_creation_count,
    p.audit_log_modification_flag, p.break_glass_account_usage_flag,
    p.least_privilege_violation_flag, p.sensitive_group_membership_change_flag,
    p.api_key_generation_frequency, p.firewall_rule_change_count,
    p.no_ticket_new_system_access_flag,
    -- 10. physical & environmental
    pe.badge_restricted_area_access_count, pe.after_hours_building_entry_flag,
    pe.badge_digital_location_mismatch_flag, pe.tailgating_detected_flag,
    pe.server_room_access_out_of_role_flag, pe.offhours_parking_entry_correlation_flag,
    pe.multiple_restricted_door_attempts_count, pe.visitor_sponsor_frequency_anomaly_flag,
    pe.asset_checkout_count, pe.sensitive_document_print_copy_count
FROM risk_feature_snapshot s
JOIN users u                                    ON u.id = s.user_id
LEFT JOIN feat_access_resource a                ON a.snapshot_id  = s.id
LEFT JOIN feat_temporal t                       ON t.snapshot_id  = s.id
LEFT JOIN feat_data_movement d                  ON d.snapshot_id  = s.id
LEFT JOIN feat_authentication_identity ai       ON ai.snapshot_id = s.id
LEFT JOIN feat_device_network dn                ON dn.snapshot_id = s.id
LEFT JOIN feat_behavioral_biometrics b          ON b.snapshot_id  = s.id
LEFT JOIN feat_hr_org_context h                 ON h.snapshot_id  = s.id
LEFT JOIN feat_communication_collaboration c    ON c.snapshot_id  = s.id
LEFT JOIN feat_privilege_permission p           ON p.snapshot_id  = s.id
LEFT JOIN feat_physical_environmental pe        ON pe.snapshot_id = s.id;
