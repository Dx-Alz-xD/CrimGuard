-- =========================================================
-- CrimGuard — 04: Raw activity events (access logs)
-- Append-only telemetry from the endpoint agent, IdP, EDR, mail/chat,
-- and badge systems. Daily feature snapshots are aggregated from here.
--
-- Indexing: BRIN on occurred_at (cheap for append-only time series) plus
-- btree (user_id, occurred_at) for per-user aggregation. At scale,
-- convert these to PARTITION BY RANGE (occurred_at) monthly partitions.
-- =========================================================

CREATE TABLE user_sessions (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id           BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id         BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    idp_session_id    TEXT,                -- Okta session id (for freeze / revoke)
    started_at        TIMESTAMPTZ NOT NULL,
    ended_at          TIMESTAMPTZ,
    source_ip         INET,
    country_code      CHAR(2),
    city              TEXT,
    latitude          NUMERIC(8,5),
    longitude         NUMERIC(8,5),
    is_vpn            BOOLEAN,
    user_agent        TEXT,
    is_frozen         BOOLEAN NOT NULL DEFAULT false,
    CHECK (ended_at IS NULL OR ended_at >= started_at)
);
CREATE INDEX idx_sessions_user_time ON user_sessions (user_id, started_at DESC);
CREATE INDEX idx_sessions_open ON user_sessions (user_id) WHERE ended_at IS NULL;

CREATE TABLE file_access_events (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id      BIGINT REFERENCES user_sessions(id) ON DELETE SET NULL,
    device_id       BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    resource_id     BIGINT REFERENCES resources(id) ON DELETE SET NULL,
    action          file_action NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    bytes           BIGINT CHECK (bytes >= 0),
    file_path       TEXT,
    previous_path   TEXT,            -- set for rename / move
    search_query    TEXT,            -- set for action = 'search'
    process_name    TEXT,
    files_in_batch  INTEGER CHECK (files_in_batch >= 0)  -- bulk directory ops
);
CREATE INDEX idx_file_events_user_time ON file_access_events (user_id, occurred_at);
CREATE INDEX idx_file_events_resource  ON file_access_events (resource_id, occurred_at);
CREATE INDEX brin_file_events_time     ON file_access_events USING brin (occurred_at);

-- Every way data leaves: downloads, uploads, email attachments, USB,
-- print, personal cloud, share links, GenAI uploads (Shadow AI).
CREATE TABLE data_transfer_events (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id              BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id            BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    resource_id          BIGINT REFERENCES resources(id) ON DELETE SET NULL,
    external_domain_id   BIGINT REFERENCES external_domains(id) ON DELETE SET NULL,
    channel              transfer_channel NOT NULL,
    occurred_at          TIMESTAMPTZ NOT NULL,
    bytes                BIGINT NOT NULL DEFAULT 0 CHECK (bytes >= 0),
    file_name            TEXT,
    destination          TEXT,        -- domain, recipient, USB serial, printer
    is_compressed        BOOLEAN NOT NULL DEFAULT false,
    is_encrypted         BOOLEAN NOT NULL DEFAULT false,
    renamed_before_export BOOLEAN NOT NULL DEFAULT false,
    sensitivity_detected sensitivity_level,
    enforcement          enforcement_action NOT NULL DEFAULT 'logged'
);
CREATE INDEX idx_transfer_user_time ON data_transfer_events (user_id, occurred_at);
CREATE INDEX idx_transfer_channel   ON data_transfer_events (channel, occurred_at);
CREATE INDEX brin_transfer_time     ON data_transfer_events USING brin (occurred_at);

-- Clipboard activity, including paste bursts into GenAI tools.
CREATE TABLE clipboard_events (
    id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id              BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    external_domain_id     BIGINT REFERENCES external_domains(id) ON DELETE SET NULL,
    occurred_at            TIMESTAMPTZ NOT NULL,
    char_count             INTEGER NOT NULL CHECK (char_count >= 0),
    source_app             TEXT,
    destination_app        TEXT,
    content_classification sensitivity_level,
    detected_patterns      TEXT[],    -- e.g. {'api_key','ssn','source_code'}; never raw content
    enforcement            enforcement_action NOT NULL DEFAULT 'logged'
);
CREATE INDEX idx_clipboard_user_time ON clipboard_events (user_id, occurred_at);
CREATE INDEX brin_clipboard_time     ON clipboard_events USING brin (occurred_at);

CREATE TABLE auth_events (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id          BIGINT REFERENCES user_sessions(id) ON DELETE SET NULL,
    device_id           BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    event_type          auth_event_type NOT NULL,
    occurred_at         TIMESTAMPTZ NOT NULL,
    source_ip           INET,
    country_code        CHAR(2),
    city                TEXT,
    latitude            NUMERIC(8,5),
    longitude           NUMERIC(8,5),
    is_vpn              BOOLEAN,
    user_agent          TEXT,
    service_account_id  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    idp_event_id        TEXT,
    ticket_id           BIGINT REFERENCES tickets(id) ON DELETE SET NULL  -- for escalation requests
);
CREATE INDEX idx_auth_user_time ON auth_events (user_id, occurred_at);
CREATE INDEX brin_auth_time     ON auth_events USING brin (occurred_at);

CREATE TABLE network_events (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id              BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id            BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    external_domain_id   BIGINT REFERENCES external_domains(id) ON DELETE SET NULL,
    occurred_at          TIMESTAMPTZ NOT NULL,
    source_ip            INET,
    destination_ip       INET,
    destination_domain   TEXT,
    destination_port     INTEGER CHECK (destination_port BETWEEN 0 AND 65535),
    protocol             TEXT,
    bytes_out            BIGINT NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    bytes_in             BIGINT NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
    is_dns_query         BOOLEAN NOT NULL DEFAULT false,
    dns_threat_score     NUMERIC(4,3) CHECK (dns_threat_score BETWEEN 0 AND 1),  -- DGA / tunneling
    process_name         TEXT
);
CREATE INDEX idx_network_user_time ON network_events (user_id, occurred_at);
CREATE INDEX brin_network_time     ON network_events USING brin (occurred_at);

-- Misc endpoint-agent telemetry: USB, screenshots, CLI, unapproved apps.
CREATE TABLE endpoint_events (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id    BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    event_type   endpoint_event_type NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL,
    app_name     TEXT,
    is_sanctioned_app BOOLEAN,
    details      JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_endpoint_user_time ON endpoint_events (user_id, occurred_at);
CREATE INDEX brin_endpoint_time     ON endpoint_events USING brin (occurred_at);

-- Alerts imported from the customer's EDR (CrowdStrike, Defender, ...).
CREATE TABLE edr_alerts (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id          BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         BIGINT REFERENCES users(id) ON DELETE SET NULL,
    device_id       BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    vendor          TEXT NOT NULL,
    external_id     TEXT NOT NULL,
    severity        risk_level NOT NULL,
    title           TEXT NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    raw             JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (org_id, vendor, external_id)
);
CREATE INDEX idx_edr_user_time ON edr_alerts (user_id, occurred_at);

-- Aggregated micro-behaviour windows (e.g. 5 min). Raw keystrokes and
-- mouse paths are never stored, only timing statistics.
CREATE TABLE biometric_samples (
    id                         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id                 BIGINT REFERENCES user_sessions(id) ON DELETE SET NULL,
    device_id                  BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    window_start               TIMESTAMPTZ NOT NULL,
    window_seconds             INTEGER NOT NULL DEFAULT 300 CHECK (window_seconds > 0),
    keystroke_interval_mean_ms DOUBLE PRECISION,
    keystroke_interval_std_ms  DOUBLE PRECISION,
    key_dwell_mean_ms          DOUBLE PRECISION,
    mouse_velocity_mean_px_s   DOUBLE PRECISION,
    mouse_velocity_std_px_s    DOUBLE PRECISION,
    scroll_events              INTEGER CHECK (scroll_events >= 0),
    scroll_velocity_mean       DOUBLE PRECISION,
    app_switches               INTEGER CHECK (app_switches >= 0),
    idle_seconds               INTEGER CHECK (idle_seconds >= 0),
    open_window_count          INTEGER CHECK (open_window_count >= 0),
    copy_paste_events          INTEGER CHECK (copy_paste_events >= 0)
);
CREATE INDEX idx_biometric_user_time ON biometric_samples (user_id, window_start);
CREATE INDEX brin_biometric_time     ON biometric_samples USING brin (window_start);

-- Metadata only (no message bodies): volume, direction, keyword hits.
CREATE TABLE communication_events (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                 BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_domain_id      BIGINT REFERENCES external_domains(id) ON DELETE SET NULL,
    channel                 communication_channel NOT NULL,
    event_type              communication_event_type NOT NULL,
    occurred_at             TIMESTAMPTZ NOT NULL,
    is_external             BOOLEAN NOT NULL DEFAULT false,
    counterparty_address    TEXT,
    counterparty_domain     TEXT,
    is_new_contact          BOOLEAN NOT NULL DEFAULT false,
    recipient_count         INTEGER CHECK (recipient_count >= 0),
    attachment_count        INTEGER NOT NULL DEFAULT 0 CHECK (attachment_count >= 0),
    attachment_bytes        BIGINT NOT NULL DEFAULT 0 CHECK (attachment_bytes >= 0),
    sensitive_keyword_hits  INTEGER NOT NULL DEFAULT 0 CHECK (sensitive_keyword_hits >= 0)
);
CREATE INDEX idx_comm_user_time ON communication_events (user_id, occurred_at);
CREATE INDEX brin_comm_time     ON communication_events USING brin (occurred_at);

-- Permission and admin activity. ticket_id NULL on a
-- 'new_system_access_granted' row drives no_ticket_new_system_access_flag.
CREATE TABLE privilege_events (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- the actor
    target_user_id      BIGINT REFERENCES users(id) ON DELETE SET NULL,
    resource_id         BIGINT REFERENCES resources(id) ON DELETE SET NULL,
    ticket_id           BIGINT REFERENCES tickets(id) ON DELETE SET NULL,
    event_type          privilege_event_type NOT NULL,
    occurred_at         TIMESTAMPTZ NOT NULL,
    target_group        TEXT,
    system_name         TEXT,
    details             JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_priv_user_time ON privilege_events (user_id, occurred_at);
CREATE INDEX brin_priv_time     ON privilege_events USING brin (occurred_at);

CREATE TABLE physical_access_events (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    zone_id             BIGINT REFERENCES facility_zones(id) ON DELETE SET NULL,
    event_type          physical_event_type NOT NULL,
    occurred_at         TIMESTAMPTZ NOT NULL,
    badge_id            TEXT,
    door_name           TEXT,
    access_granted      BOOLEAN,
    visitor_name        TEXT,              -- for visitor_sponsored
    asset_tag           TEXT,              -- for asset_checkout / asset_return
    document_pages      INTEGER CHECK (document_pages >= 0),
    details             JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_physical_user_time ON physical_access_events (user_id, occurred_at);
CREATE INDEX brin_physical_time     ON physical_access_events USING brin (occurred_at);

CREATE TABLE honeytoken_triggers (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    honeytoken_id   BIGINT NOT NULL REFERENCES honeytokens(id) ON DELETE CASCADE,
    user_id         BIGINT REFERENCES users(id) ON DELETE SET NULL,  -- NULL if unattributed
    device_id       BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    interaction     TEXT NOT NULL,     -- 'opened', 'copied', 'exfiltrated', 'key_used'
    source_ip       INET,
    details         JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_honey_trigger_user ON honeytoken_triggers (user_id, occurred_at);
CREATE INDEX idx_honey_trigger_token ON honeytoken_triggers (honeytoken_id, occurred_at);
