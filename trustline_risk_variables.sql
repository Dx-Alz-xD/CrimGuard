-- =========================================================
-- TrustLine / CrimGuard — Risk Score Feature Variables
-- PostgreSQL schema: one snapshot row per user per period
-- (day / session, depending on how you batch it)
-- =========================================================

CREATE TABLE risk_feature_snapshot (
    id                  SERIAL PRIMARY KEY,
    user_id             INTEGER NOT NULL REFERENCES users(id),
    snapshot_date       DATE NOT NULL,

    -- ===== 1. ACCESS & RESOURCE PATTERNS =====
    files_accessed_count                   INTEGER,
    distinct_resource_types_touched        INTEGER,
    read_write_delete_ratio                NUMERIC,
    out_of_scope_resource_access_count     INTEGER,
    first_time_resource_access_flag        BOOLEAN,
    repeated_sensitive_file_access_count   INTEGER,
    bulk_directory_access_flag             BOOLEAN,
    confidential_resource_access_count     INTEGER,
    unusual_search_query_count             INTEGER,
    download_volume_vs_baseline            NUMERIC,

    -- ===== 2. TEMPORAL SIGNALS =====
    access_time_deviation_from_normal_hours NUMERIC,
    weekend_holiday_access_flag            BOOLEAN,
    session_duration_vs_baseline           NUMERIC,
    time_to_first_sensitive_access_sec     INTEGER,
    after_hours_access_frequency           NUMERIC,
    activity_start_end_time_shift          NUMERIC,
    leave_period_activity_flag             BOOLEAN,
    unusual_inactivity_gap_flag            BOOLEAN,
    burst_activity_flag                    BOOLEAN,
    day_of_week_pattern_change_score       NUMERIC,

    -- ===== 3. DATA MOVEMENT & EXFILTRATION =====
    daily_download_volume_mb               NUMERIC,
    external_upload_volume_mb              NUMERIC,
    external_email_attachment_frequency    NUMERIC,
    usb_write_activity_count               INTEGER,
    print_job_volume                       INTEGER,
    large_clipboard_copy_event_count       INTEGER,
    pre_transfer_compression_flag          BOOLEAN,
    file_rename_before_export_count        INTEGER,
    personal_cloud_transfer_flag           BOOLEAN,
    external_share_link_count              INTEGER,

    -- ===== 4. AUTHENTICATION & IDENTITY =====
    failed_login_attempt_count             INTEGER,
    new_device_login_flag                  BOOLEAN,
    new_geolocation_login_flag             BOOLEAN,
    concurrent_session_diff_location_flag  BOOLEAN,
    mfa_bypass_dismissal_count             INTEGER,
    password_reset_frequency               INTEGER,
    shared_service_account_usage_flag      BOOLEAN,
    vpn_usage_anomaly_score                NUMERIC,
    session_token_reuse_flag               BOOLEAN,
    privilege_escalation_request_count     INTEGER,

    -- ===== 5. DEVICE & NETWORK =====
    new_device_fingerprint_flag            BOOLEAN,
    unmanaged_device_access_flag           BOOLEAN,
    personal_device_sensitive_access_flag  BOOLEAN,
    unusual_ip_range_flag                  BOOLEAN,
    impossible_travel_flag                 BOOLEAN,
    user_agent_inconsistency_flag          BOOLEAN,
    bandwidth_usage_spike                  NUMERIC,
    suspicious_dns_request_count           INTEGER,
    unauthorized_app_usage_flag            BOOLEAN,
    edr_alert_correlation_count            INTEGER,

    -- ===== 6. BEHAVIORAL BIOMETRICS =====
    keystroke_cadence_deviation            NUMERIC,
    mouse_velocity_deviation               NUMERIC,
    scroll_behavior_consistency_score      NUMERIC,
    app_switch_frequency                   INTEGER,
    idle_time_pattern_score                NUMERIC,
    cli_terminal_usage_frequency           INTEGER,
    copy_paste_frequency_volume            INTEGER,
    screenshot_recording_activity_count    INTEGER,
    open_app_window_count                  INTEGER,
    digital_signature_deviation_score      NUMERIC,

    -- ===== 7. HR & ORGANIZATIONAL CONTEXT =====
    recent_role_change_flag                BOOLEAN,
    termination_date_on_file               DATE,
    recent_negative_review_flag            BOOLEAN,
    pto_dump_flag                          BOOLEAN,
    recent_disciplinary_action_flag        BOOLEAN,
    tenure_months                          INTEGER,
    recent_project_assignment_flag         BOOLEAN,
    manager_change_flag                    BOOLEAN,
    compensation_change_flag               BOOLEAN,
    employment_type                        TEXT,  -- 'full_time' | 'contractor' | 'temp'

    -- ===== 8. COMMUNICATION & COLLABORATION =====
    internal_message_volume                INTEGER,
    external_message_increase_score        NUMERIC,
    email_auto_forward_change_flag         BOOLEAN,
    sensitive_keyword_message_count        INTEGER,
    credential_sharing_in_chat_flag        BOOLEAN,
    meeting_attendance_change_score        NUMERIC,
    ephemeral_app_usage_flag               BOOLEAN,
    calendar_activity_anomaly_flag         BOOLEAN,
    new_external_contact_growth_rate       NUMERIC,
    competitor_domain_contact_count        INTEGER,

    -- ===== 9. PRIVILEGE & PERMISSION =====
    permission_change_count                INTEGER,
    admin_panel_access_flag                BOOLEAN,
    new_account_creation_count             INTEGER,
    audit_log_modification_flag            BOOLEAN,
    break_glass_account_usage_flag         BOOLEAN,
    least_privilege_violation_flag         BOOLEAN,
    sensitive_group_membership_change_flag BOOLEAN,
    api_key_generation_frequency           INTEGER,
    firewall_rule_change_count             INTEGER,
    no_ticket_new_system_access_flag       BOOLEAN,

    -- ===== 10. PHYSICAL & ENVIRONMENTAL =====
    badge_restricted_area_access_count     INTEGER,
    after_hours_building_entry_flag        BOOLEAN,
    badge_digital_location_mismatch_flag   BOOLEAN,
    tailgating_detected_flag               BOOLEAN,
    server_room_access_out_of_role_flag    BOOLEAN,
    offhours_parking_entry_correlation_flag BOOLEAN,
    multiple_restricted_door_attempts_count INTEGER,
    visitor_sponsor_frequency_anomaly_flag BOOLEAN,
    asset_checkout_count                   INTEGER,
    sensitive_document_print_copy_count    INTEGER,

    UNIQUE (user_id, snapshot_date)
);

-- Index for the query pattern you'll run most: pulling a user's
-- recent snapshots to compute rolling z-scores / baselines.
CREATE INDEX idx_risk_feature_user_date
    ON risk_feature_snapshot (user_id, snapshot_date);
