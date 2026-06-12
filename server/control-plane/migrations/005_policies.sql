-- Policies are versioned, activatable risk rule sets for a tenant (optionally
-- per-app). At most one policy may be active per (tenant_id, app scope).
-- Protection profiles are reusable named module bundles referenced by builds;
-- they live alongside policies as control-plane authoring artifacts.

CREATE TABLE IF NOT EXISTS protection_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    modules_enabled TEXT[] NOT NULL DEFAULT '{}',
    default_mode    INT NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_profiles_tenant ON protection_profiles (tenant_id);

ALTER TABLE protection_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE protection_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY profiles_tenant_isolation ON protection_profiles
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));

CREATE TABLE IF NOT EXISTS policies (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Empty string app scope means a tenant-wide default policy.
    app_id            TEXT NOT NULL DEFAULT '',
    name              TEXT NOT NULL,
    version           INT NOT NULL DEFAULT 1,
    enforcement_mode  INT NOT NULL DEFAULT 1,
    rules             JSONB NOT NULL DEFAULT '[]',
    risk_thresholds   JSONB NOT NULL DEFAULT '{}',
    modules_enabled   TEXT[] NOT NULL DEFAULT '{}',
    policy_hash       TEXT NOT NULL DEFAULT '',
    is_active         BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_policies_scope ON policies (tenant_id, app_id);
-- At most one active policy per (tenant, app scope).
CREATE UNIQUE INDEX IF NOT EXISTS uq_policies_active
    ON policies (tenant_id, app_id) WHERE is_active;
-- Versions are unique within a (tenant, app scope).
CREATE UNIQUE INDEX IF NOT EXISTS uq_policies_version
    ON policies (tenant_id, app_id, version);

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_tenant_isolation ON policies
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
