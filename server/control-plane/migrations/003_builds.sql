-- Builds are immutable records of a protected build of an app.

CREATE TABLE IF NOT EXISTS builds (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id                  UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    build_hash              TEXT NOT NULL,
    version_name            TEXT NOT NULL DEFAULT '',
    version_code            BIGINT NOT NULL DEFAULT 0,
    protection_profile_id   TEXT NOT NULL DEFAULT '',
    manifest                JSONB NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, build_hash)
);

CREATE INDEX IF NOT EXISTS idx_builds_tenant ON builds (tenant_id);
CREATE INDEX IF NOT EXISTS idx_builds_app ON builds (tenant_id, app_id);
CREATE INDEX IF NOT EXISTS idx_builds_hash ON builds (tenant_id, build_hash);

ALTER TABLE builds ENABLE ROW LEVEL SECURITY;
ALTER TABLE builds FORCE ROW LEVEL SECURITY;
CREATE POLICY builds_tenant_isolation ON builds
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
