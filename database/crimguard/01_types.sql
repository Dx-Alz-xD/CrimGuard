-- =========================================================
-- CrimGuard — 01: Extensions & enumerated types
-- Run files in numeric order (psql -f, or drop the folder into
-- /docker-entrypoint-initdb.d/ which runs them alphabetically).
-- Requires PostgreSQL 15+ (UNIQUE NULLS NOT DISTINCT).
-- =========================================================

-- ----- Tenancy / people -----
CREATE TYPE industry_vertical AS ENUM (
    'enterprise', 'healthcare', 'finance', 'saas', 'university', 'other'
);

CREATE TYPE employment_type AS ENUM ('full_time', 'contractor', 'temp');

CREATE TYPE employment_status AS ENUM (
    'active', 'on_leave', 'notice_period', 'terminated'
);

-- ----- Assets -----
CREATE TYPE sensitivity_level AS ENUM (
    'public', 'internal', 'confidential', 'restricted'
);

CREATE TYPE resource_type AS ENUM (
    'file', 'directory', 'database', 'repository', 'saas_app',
    'api', 'network_share', 'mailbox', 'other'
);

CREATE TYPE external_domain_category AS ENUM (
    'genai_llm', 'personal_cloud', 'webmail', 'file_sharing',
    'ephemeral_messaging', 'competitor', 'social_media', 'other'
);

CREATE TYPE facility_zone_type AS ENUM (
    'general', 'restricted', 'server_room', 'parking', 'lobby', 'records_room'
);

CREATE TYPE honeytoken_type AS ENUM (
    'honey_file', 'fake_api_key', 'fake_credential', 'canary_document',
    'honey_database_row'
);

-- ----- Context ledger -----
CREATE TYPE ticket_status AS ENUM (
    'open', 'in_progress', 'blocked', 'resolved', 'closed', 'cancelled'
);

CREATE TYPE hr_event_type AS ENUM (
    'hire', 'role_change', 'manager_change', 'compensation_change',
    'performance_review', 'disciplinary_action', 'resignation_notice',
    'termination_scheduled', 'termination', 'pto_request', 'transfer'
);

CREATE TYPE leave_type AS ENUM (
    'pto', 'sick', 'parental', 'sabbatical', 'garden_leave', 'unpaid', 'other'
);

-- ----- Raw events -----
CREATE TYPE file_action AS ENUM (
    'read', 'write', 'delete', 'download', 'rename', 'copy', 'move',
    'compress', 'permission_change', 'search'
);

CREATE TYPE transfer_channel AS ENUM (
    'download', 'external_upload', 'email_attachment', 'usb_write', 'print',
    'personal_cloud', 'external_share_link', 'genai_upload', 'airdrop_bluetooth'
);

CREATE TYPE enforcement_action AS ENUM (
    'allowed', 'logged', 'warned', 'redacted', 'blocked'
);

CREATE TYPE auth_event_type AS ENUM (
    'login_success', 'login_failure', 'logout', 'mfa_challenge', 'mfa_success',
    'mfa_failure', 'mfa_dismissed', 'password_reset', 'session_token_reuse',
    'privilege_escalation_request', 'service_account_login'
);

CREATE TYPE endpoint_event_type AS ENUM (
    'usb_device_connected', 'screenshot', 'screen_recording', 'cli_command',
    'unauthorized_app_launch', 'app_switch', 'print_job'
);

CREATE TYPE communication_channel AS ENUM (
    'email', 'chat', 'meeting', 'calendar', 'ephemeral_app'
);

CREATE TYPE communication_event_type AS ENUM (
    'message_sent', 'message_received', 'attachment_sent',
    'auto_forward_rule_created', 'auto_forward_rule_changed',
    'credential_shared', 'meeting_attended', 'meeting_missed',
    'calendar_event_created', 'calendar_event_deleted'
);

CREATE TYPE privilege_event_type AS ENUM (
    'permission_change', 'admin_panel_access', 'account_created',
    'audit_log_modified', 'break_glass_used', 'least_privilege_violation',
    'sensitive_group_membership_change', 'api_key_generated',
    'firewall_rule_change', 'new_system_access_granted'
);

CREATE TYPE physical_event_type AS ENUM (
    'badge_entry', 'badge_denied', 'tailgating_detected', 'parking_entry',
    'visitor_sponsored', 'asset_checkout', 'asset_return', 'document_print_copy'
);

-- ----- Features / detection / response -----
CREATE TYPE feature_category AS ENUM (
    'access_resource', 'temporal', 'data_movement', 'authentication_identity',
    'device_network', 'behavioral_biometrics', 'hr_org_context',
    'communication_collaboration', 'privilege_permission', 'physical_environmental'
);

CREATE TYPE feature_value_type AS ENUM (
    'count', 'flag', 'ratio', 'score', 'volume_mb', 'seconds', 'months',
    'date', 'category'
);

CREATE TYPE baseline_window AS ENUM (
    'rolling_14d', 'rolling_30d', 'rolling_90d',
    'anchored',   -- frozen reference period: catches slow drift (Case B)
    'peer_group'  -- same role / department
);

CREATE TYPE detection_method AS ENUM (
    'z_score', 'isolation_forest', 'drift_trend', 'rule', 'honeytoken'
);

CREATE TYPE context_match_type AS ENUM (
    'ticket', 'project', 'role_change', 'hr_event', 'leave_period', 'none'
);

CREATE TYPE context_verdict AS ENUM (
    'explained', 'partially_explained', 'unexplained'
);

CREATE TYPE risk_level AS ENUM ('low', 'medium', 'high', 'critical');

CREATE TYPE risk_scenario AS ENUM (
    'legitimate_spike',          -- Case A
    'slow_exfiltration',         -- Case B
    'pre_resignation_hoarding',
    'shadow_ai_leak',
    'credential_compromise',
    'privilege_abuse',
    'honeytoken_trip',
    'physical_security',
    'other'
);

CREATE TYPE alert_status AS ENUM (
    'open', 'investigating', 'escalated',
    'resolved_true_positive', 'resolved_false_positive', 'dismissed'
);

CREATE TYPE identity_action_type AS ENUM (
    'step_up_mfa', 'session_freeze', 'session_revoke',
    'force_password_reset', 'account_suspend', 'restore_access'
);

CREATE TYPE action_status AS ENUM (
    'pending', 'sent', 'completed', 'failed', 'cancelled'
);
