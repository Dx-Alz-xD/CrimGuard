-- =========================================================
-- CrimGuard — 07: Baselines, anomaly detection, context match,
-- risk scoring, alerts, and automated identity response.
--
-- Pipeline:  snapshot -> feature_baselines -> anomalies (z / IForest /
--            drift) -> context_matches -> risk_scores -> alerts
--            -> identity_actions (Okta step-up MFA / freeze)
-- =========================================================

-- Rolling, anchored, and peer baselines per feature. Exactly one subject:
-- a user, a role (peer group) or a department.
-- 'anchored' keeps a frozen reference window so slow creep (Case B:
-- 15 -> 70 files/day over 3 months) is not absorbed into "normal".
CREATE TABLE feature_baselines (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    feature_key         TEXT NOT NULL REFERENCES feature_catalog(feature_key) ON DELETE CASCADE,
    window_type         baseline_window NOT NULL,
    user_id             BIGINT REFERENCES users(id) ON DELETE CASCADE,
    role_id             BIGINT REFERENCES roles(id) ON DELETE CASCADE,
    department_id       BIGINT REFERENCES departments(id) ON DELETE CASCADE,
    period_start        DATE NOT NULL,
    period_end          DATE NOT NULL,
    sample_count        INTEGER NOT NULL CHECK (sample_count >= 0),
    mean                DOUBLE PRECISION,
    stddev              DOUBLE PRECISION CHECK (stddev >= 0),
    median              DOUBLE PRECISION,
    mad                 DOUBLE PRECISION CHECK (mad >= 0),  -- robust z-score denominator
    p95                 DOUBLE PRECISION,
    trend_slope_per_day DOUBLE PRECISION,                    -- linear drift over the window
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(user_id, role_id, department_id) = 1),
    CHECK (period_end >= period_start),
    UNIQUE NULLS NOT DISTINCT (feature_key, window_type, user_id, role_id, department_id, period_end)
);
CREATE INDEX idx_baselines_user ON feature_baselines (user_id, feature_key, period_end DESC)
    WHERE user_id IS NOT NULL;
CREATE INDEX idx_baselines_role ON feature_baselines (role_id, feature_key, period_end DESC)
    WHERE role_id IS NOT NULL;

-- One row per detector hit. feature_key is NULL only for multivariate
-- Isolation Forest hits that score the whole vector.
CREATE TABLE anomalies (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    snapshot_id             BIGINT NOT NULL REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    user_id                 BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    feature_key             TEXT REFERENCES feature_catalog(feature_key) ON DELETE CASCADE,
    baseline_id             BIGINT REFERENCES feature_baselines(id) ON DELETE SET NULL,
    detection_method        detection_method NOT NULL,
    observed_value          DOUBLE PRECISION,
    baseline_mean           DOUBLE PRECISION,
    baseline_stddev         DOUBLE PRECISION,
    z_score                 DOUBLE PRECISION,
    z_threshold             NUMERIC(4,2),                 -- 2.6 - 3.0 sigma per catalog / org
    isolation_forest_score  DOUBLE PRECISION CHECK (isolation_forest_score BETWEEN 0 AND 1),
    drift_pct_vs_anchor     DOUBLE PRECISION,             -- e.g. 3.67 = +367% vs anchored baseline
    model_version           TEXT,
    detected_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (feature_key IS NOT NULL OR detection_method = 'isolation_forest')
);
CREATE INDEX idx_anomalies_snapshot ON anomalies (snapshot_id);
CREATE INDEX idx_anomalies_user     ON anomalies (user_id, detected_at DESC);

-- Result of querying the context ledger for an anomaly.
-- proportionality_ratio = observed / what the ticket says to expect;
-- a migration ticket expecting 600 files/day with 650 observed ~ 1.08.
CREATE TABLE context_matches (
    id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    anomaly_id             BIGINT NOT NULL REFERENCES anomalies(id) ON DELETE CASCADE,
    match_type             context_match_type NOT NULL,
    ticket_id              BIGINT REFERENCES tickets(id) ON DELETE SET NULL,
    project_id             BIGINT REFERENCES projects(id) ON DELETE SET NULL,
    role_assignment_id     BIGINT REFERENCES user_role_assignments(id) ON DELETE SET NULL,
    hr_event_id            BIGINT REFERENCES hr_events(id) ON DELETE SET NULL,
    leave_period_id        BIGINT REFERENCES leave_periods(id) ON DELETE SET NULL,
    verdict                context_verdict NOT NULL,
    explanation_strength   NUMERIC(4,3) NOT NULL CHECK (explanation_strength BETWEEN 0 AND 1),
    proportionality_ratio  DOUBLE PRECISION CHECK (proportionality_ratio >= 0),
    rationale              TEXT,
    matched_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (match_type <> 'none' OR (num_nonnulls(ticket_id, project_id, role_assignment_id,
                                                 hr_event_id, leave_period_id) = 0
                                    AND verdict = 'unexplained'))
);
CREATE INDEX idx_context_matches_anomaly ON context_matches (anomaly_id);
CREATE INDEX idx_context_matches_ticket  ON context_matches (ticket_id) WHERE ticket_id IS NOT NULL;

-- Final score per snapshot. Component columns hold each term of the
-- scoring formula so every score is explainable on the dashboard.
CREATE TABLE risk_scores (
    id                        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    snapshot_id               BIGINT NOT NULL REFERENCES risk_feature_snapshot(id) ON DELETE CASCADE,
    user_id                   BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    model_version             TEXT NOT NULL,
    -- formula components
    statistical_anomaly_score DOUBLE PRECISION CHECK (statistical_anomaly_score >= 0), -- weighted z-scores
    isolation_forest_score    DOUBLE PRECISION CHECK (isolation_forest_score BETWEEN 0 AND 1),
    drift_score               DOUBLE PRECISION CHECK (drift_score >= 0),               -- slow exfiltration
    asset_criticality_weight  NUMERIC(5,2) CHECK (asset_criticality_weight > 0),       -- max resources.criticality_weight touched
    context_multiplier        NUMERIC(4,3) CHECK (context_multiplier BETWEEN 0 AND 1), -- < 1 when explained (Case A)
    hr_amplifier              NUMERIC(4,2) CHECK (hr_amplifier >= 1),                  -- termination, bad review, PTO dump
    honeytoken_override       BOOLEAN NOT NULL DEFAULT false,                          -- forces critical
    -- result
    final_score               NUMERIC(5,2) NOT NULL CHECK (final_score BETWEEN 0 AND 100),
    risk_level                risk_level NOT NULL,
    scenario                  risk_scenario,
    feature_contributions     JSONB NOT NULL DEFAULT '{}'::jsonb,  -- {"files_accessed_count": 12.4, ...}
    -- structured payload for the dashboard: timeline, anomaly markers, risk values
    dashboard_payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    scored_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (snapshot_id, model_version)
);
CREATE INDEX idx_risk_scores_user  ON risk_scores (user_id, scored_at DESC);
CREATE INDEX idx_risk_scores_high  ON risk_scores (risk_level, scored_at DESC)
    WHERE risk_level IN ('high', 'critical');

CREATE TABLE alerts (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id            BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id           BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- subject
    risk_score_id     BIGINT REFERENCES risk_scores(id) ON DELETE SET NULL,
    title             TEXT NOT NULL,
    summary           TEXT,
    severity          risk_level NOT NULL,
    scenario          risk_scenario NOT NULL DEFAULT 'other',
    status            alert_status NOT NULL DEFAULT 'open',
    assigned_to       BIGINT REFERENCES users(id) ON DELETE SET NULL,          -- analyst
    first_seen_at     TIMESTAMPTZ NOT NULL,
    last_seen_at      TIMESTAMPTZ NOT NULL,
    resolved_at       TIMESTAMPTZ,
    resolution_notes  TEXT,  -- analyst feedback; false positives feed model tuning
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (last_seen_at >= first_seen_at),
    CHECK ((status IN ('open', 'investigating', 'escalated')) = (resolved_at IS NULL))
);
CREATE INDEX idx_alerts_queue ON alerts (org_id, severity, created_at DESC)
    WHERE status IN ('open', 'investigating', 'escalated');
CREATE INDEX idx_alerts_user  ON alerts (user_id, created_at DESC);

-- What an alert is built from.
CREATE TABLE alert_evidence (
    id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id               BIGINT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    anomaly_id             BIGINT REFERENCES anomalies(id) ON DELETE CASCADE,
    honeytoken_trigger_id  BIGINT REFERENCES honeytoken_triggers(id) ON DELETE CASCADE,
    edr_alert_id           BIGINT REFERENCES edr_alerts(id) ON DELETE CASCADE,
    note                   TEXT,
    added_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(anomaly_id, honeytoken_trigger_id, edr_alert_id) = 1)
);
CREATE INDEX idx_alert_evidence_alert ON alert_evidence (alert_id);

-- Dynamic identity throttle rules, e.g. score >= 70 -> step-up MFA,
-- score >= 90 or honeytoken_trip -> freeze session.
CREATE TABLE response_policies (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id          BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    min_final_score NUMERIC(5,2) CHECK (min_final_score BETWEEN 0 AND 100),
    scenario        risk_scenario,      -- NULL = any scenario
    action          identity_action_type NOT NULL,
    requires_analyst_approval BOOLEAN NOT NULL DEFAULT false,
    is_enabled      BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name),
    CHECK (min_final_score IS NOT NULL OR scenario IS NOT NULL)
);

-- Every call made to Okta (or another IdP) and its outcome.
CREATE TABLE identity_actions (
    id                   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id              BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alert_id             BIGINT REFERENCES alerts(id) ON DELETE SET NULL,
    policy_id            BIGINT REFERENCES response_policies(id) ON DELETE SET NULL,
    session_id           BIGINT REFERENCES user_sessions(id) ON DELETE SET NULL,
    action               identity_action_type NOT NULL,
    provider             TEXT NOT NULL DEFAULT 'okta',
    requested_by         BIGINT REFERENCES users(id) ON DELETE SET NULL,  -- NULL = automated policy
    status               action_status NOT NULL DEFAULT 'pending',
    provider_request_id  TEXT,
    request_payload      JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_payload     JSONB,
    error_message        TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at         TIMESTAMPTZ
);
CREATE INDEX idx_identity_actions_user    ON identity_actions (user_id, created_at DESC);
CREATE INDEX idx_identity_actions_pending ON identity_actions (created_at)
    WHERE status IN ('pending', 'sent');

-- Who looked at / changed what inside CrimGuard itself. Insider-risk
-- tooling must be auditable (HIPAA, GDPR, works councils).
CREATE TABLE platform_audit_log (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id          BIGINT REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action          TEXT NOT NULL,     -- 'view_user_timeline', 'update_alert', 'freeze_session'
    target_table    TEXT,
    target_id       BIGINT,
    source_ip       INET,
    details         JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_org_time ON platform_audit_log (org_id, occurred_at DESC);
