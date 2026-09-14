-- =========================================================
-- CrimGuard — 02: Core entities
-- Tenants, people, roles, devices, protected assets, and the
-- lookup catalogs the detectors classify events against.
-- =========================================================

CREATE TABLE organizations (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            TEXT NOT NULL,
    industry        industry_vertical NOT NULL DEFAULT 'other',
    timezone        TEXT NOT NULL DEFAULT 'UTC',
    -- normal working window, used for after-hours signals
    work_day_start  TIME NOT NULL DEFAULT '09:00',
    work_day_end    TIME NOT NULL DEFAULT '18:00',
    okta_domain     TEXT,
    workday_tenant  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE departments (
    id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id                BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    parent_department_id  BIGINT REFERENCES departments(id) ON DELETE SET NULL,
    name                  TEXT NOT NULL,
    UNIQUE (org_id, name)
);

CREATE TABLE users (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id             BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    department_id      BIGINT REFERENCES departments(id) ON DELETE SET NULL,
    manager_id         BIGINT REFERENCES users(id) ON DELETE SET NULL,
    email              TEXT NOT NULL,
    full_name          TEXT NOT NULL,
    job_title          TEXT,
    employment_type    employment_type NOT NULL DEFAULT 'full_time',
    employment_status  employment_status NOT NULL DEFAULT 'active',
    hire_date          DATE,
    termination_date   DATE,
    is_privileged      BOOLEAN NOT NULL DEFAULT false,
    is_service_account BOOLEAN NOT NULL DEFAULT false,
    is_analyst         BOOLEAN NOT NULL DEFAULT false,  -- can use the CrimGuard console
    okta_user_id       TEXT,
    workday_worker_id  TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, email),
    UNIQUE (org_id, okta_user_id),
    UNIQUE (org_id, workday_worker_id),
    CHECK (termination_date IS NULL OR hire_date IS NULL OR termination_date >= hire_date)
);
CREATE INDEX idx_users_department ON users (department_id);
CREATE INDEX idx_users_manager    ON users (manager_id);

CREATE TABLE roles (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id       BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT,
    is_privileged BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (org_id, name)
);

-- Role history. A new row = a role change (feeds recent_role_change_flag).
-- valid_to NULL means the assignment is current.
CREATE TABLE user_role_assignments (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    valid_from  DATE NOT NULL,
    valid_to    DATE,
    source      TEXT NOT NULL DEFAULT 'workday',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_to >= valid_from)
);
CREATE INDEX idx_role_assign_user ON user_role_assignments (user_id, valid_from DESC);
CREATE UNIQUE INDEX uq_role_assign_current
    ON user_role_assignments (user_id, role_id) WHERE valid_to IS NULL;

CREATE TABLE devices (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id              BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    primary_user_id     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    fingerprint_hash    TEXT NOT NULL,
    hostname            TEXT,
    os                  TEXT,
    is_managed          BOOLEAN NOT NULL DEFAULT false,  -- enrolled in MDM / has agent
    is_personal         BOOLEAN NOT NULL DEFAULT false,  -- BYOD
    agent_version       TEXT,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, fingerprint_hash)
);
CREATE INDEX idx_devices_user ON devices (primary_user_id);

-- Protected assets. criticality_weight is the asset-value term of the
-- risk engine: touching a restricted payroll DB outweighs a wiki page.
CREATE TABLE resources (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id              BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_department_id BIGINT REFERENCES departments(id) ON DELETE SET NULL,
    resource_type       resource_type NOT NULL,
    uri                 TEXT NOT NULL,        -- path, DB name, repo URL, app id
    display_name        TEXT,
    sensitivity         sensitivity_level NOT NULL DEFAULT 'internal',
    criticality_weight  NUMERIC(5,2) NOT NULL DEFAULT 1.00 CHECK (criticality_weight > 0),
    is_honeytoken       BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, uri)
);
CREATE INDEX idx_resources_sensitive
    ON resources (org_id, sensitivity) WHERE sensitivity IN ('confidential', 'restricted');

-- Which resources a role is expected to touch. Access outside this set
-- feeds out_of_scope_resource_access_count / least_privilege_violation_flag.
CREATE TABLE role_resource_entitlements (
    role_id      BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    resource_id  BIGINT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    can_read     BOOLEAN NOT NULL DEFAULT true,
    can_write    BOOLEAN NOT NULL DEFAULT false,
    can_delete   BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (role_id, resource_id)
);

-- Decoys (honey-files, fake API keys). Any touch is high-signal and
-- never context-explainable.
CREATE TABLE honeytokens (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id       BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_id  BIGINT REFERENCES resources(id) ON DELETE SET NULL,
    token_type   honeytoken_type NOT NULL,
    token_fingerprint TEXT NOT NULL,   -- hash of the fake key / file canary id
    placement    TEXT,                 -- e.g. 'finance share /Q4/keys.env'
    is_active    BOOLEAN NOT NULL DEFAULT true,
    planted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at   TIMESTAMPTZ,
    UNIQUE (org_id, token_fingerprint)
);

-- Classifies outbound destinations: unsanctioned GenAI tools (Shadow AI),
-- personal cloud, ephemeral messengers, competitor domains.
-- org_id NULL = global CrimGuard-maintained entry.
CREATE TABLE external_domains (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id        BIGINT REFERENCES organizations(id) ON DELETE CASCADE,
    domain        TEXT NOT NULL,
    app_name      TEXT,
    category      external_domain_category NOT NULL,
    is_sanctioned BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (org_id, domain)
);

CREATE TABLE facility_zones (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id             BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    zone_type          facility_zone_type NOT NULL DEFAULT 'general',
    site               TEXT,
    city               TEXT,
    country_code       CHAR(2),
    UNIQUE (org_id, name)
);

-- Roles allowed into a restricted zone (server_room_access_out_of_role_flag).
CREATE TABLE zone_role_access (
    zone_id  BIGINT NOT NULL REFERENCES facility_zones(id) ON DELETE CASCADE,
    role_id  BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (zone_id, role_id)
);

-- Org calendar for weekend_holiday_access_flag.
CREATE TABLE org_holidays (
    org_id        BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    holiday_date  DATE NOT NULL,
    name          TEXT NOT NULL,
    PRIMARY KEY (org_id, holiday_date)
);
