-- Apps are registered applications bound to a tenant + platform.

CREATE TABLE IF NOT EXISTS apps (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    platform            INT NOT NULL DEFAULT 0,
    package_id          TEXT NOT NULL,
    signing_identities  TEXT[] NOT NULL DEFAULT '{}',
    status              TEXT NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, platform, package_id)
);

CREATE INDEX IF NOT EXISTS idx_apps_tenant ON apps (tenant_id);
CREATE INDEX IF NOT EXISTS idx_apps_tenant_status ON apps (tenant_id, status);

ALTER TABLE apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps FORCE ROW LEVEL SECURITY;
CREATE POLICY apps_tenant_isolation ON apps
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
