-- =========================================================
-- CrimGuard — 03: Live context ledger
-- The "why" behind activity: projects, tickets, HR status, leave.
-- Anomalies are matched against these rows before scoring.
--   Case A: 500-800 files/day + active migration ticket  -> explained
--   Case B: 15 -> 70 files/day, no ticket/role/project change -> unexplained
-- Role changes live in user_role_assignments (02_core.sql).
-- =========================================================

CREATE TABLE projects (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id       BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT,
    owner_id     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    starts_on    DATE NOT NULL,
    ends_on      DATE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (ends_on IS NULL OR ends_on >= starts_on)
);

CREATE TABLE project_members (
    project_id  BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_on   DATE NOT NULL,
    left_on     DATE,
    PRIMARY KEY (project_id, user_id, joined_on),
    CHECK (left_on IS NULL OR left_on >= joined_on)
);
CREATE INDEX idx_project_members_user ON project_members (user_id, joined_on);

-- Work tickets synced from Jira / ServiceNow. The expected_* columns are
-- what lets a spike be judged proportionate to the assigned work.
CREATE TABLE tickets (
    id                        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id                    BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id                BIGINT REFERENCES projects(id) ON DELETE SET NULL,
    source_system             TEXT NOT NULL DEFAULT 'jira',
    external_key              TEXT NOT NULL,          -- e.g. 'DBM-142'
    title                     TEXT NOT NULL,
    ticket_type               TEXT,                   -- 'db_migration', 'audit', 'access_request'
    status                    ticket_status NOT NULL DEFAULT 'open',
    approved_by               BIGINT REFERENCES users(id) ON DELETE SET NULL,
    expected_daily_file_volume INTEGER CHECK (expected_daily_file_volume >= 0),
    expected_access_multiplier NUMERIC(6,2) CHECK (expected_access_multiplier > 0),
    opened_at                 TIMESTAMPTZ NOT NULL,
    due_at                    TIMESTAMPTZ,
    closed_at                 TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, source_system, external_key),
    CHECK (closed_at IS NULL OR closed_at >= opened_at)
);
CREATE INDEX idx_tickets_active ON tickets (org_id, status)
    WHERE status IN ('open', 'in_progress', 'blocked');

CREATE TABLE ticket_assignments (
    ticket_id       BIGINT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_at     TIMESTAMPTZ NOT NULL,
    unassigned_at   TIMESTAMPTZ,
    PRIMARY KEY (ticket_id, user_id, assigned_at),
    CHECK (unassigned_at IS NULL OR unassigned_at >= assigned_at)
);
CREATE INDEX idx_ticket_assign_user ON ticket_assignments (user_id, assigned_at);

-- Resources a ticket legitimately justifies touching.
CREATE TABLE ticket_resource_scope (
    ticket_id    BIGINT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    resource_id  BIGINT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    PRIMARY KEY (ticket_id, resource_id)
);

-- HR timeline synced from Workday. One row per event; details holds the
-- source-specific payload (review rating, old/new manager, comp delta...).
CREATE TABLE hr_events (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type      hr_event_type NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_date  DATE NOT NULL,
    is_negative     BOOLEAN NOT NULL DEFAULT false,  -- poor review, demotion, pay cut, PIP
    review_rating   NUMERIC(3,1),                    -- for performance_review
    details         JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_system   TEXT NOT NULL DEFAULT 'workday',
    external_ref    TEXT
);
CREATE INDEX idx_hr_events_user ON hr_events (user_id, effective_date DESC);
CREATE INDEX idx_hr_events_type ON hr_events (event_type, effective_date DESC);

-- Leave periods: activity during leave, and PTO dumps (burning all
-- remaining PTO right before leaving).
CREATE TABLE leave_periods (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    leave_type      leave_type NOT NULL,
    starts_on       DATE NOT NULL,
    ends_on         DATE NOT NULL,
    days_requested  NUMERIC(5,1),
    balance_before  NUMERIC(5,1),
    requested_at    TIMESTAMPTZ,
    approved        BOOLEAN NOT NULL DEFAULT true,
    CHECK (ends_on >= starts_on)
);
CREATE INDEX idx_leave_user_range ON leave_periods (user_id, starts_on, ends_on);
