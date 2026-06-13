-- Signed remote kill switches. Each row is the latest Ed25519-signed
-- disable/enable command for a scope (tenant, optional app, optional build).
-- The signature is computed by the control plane over a canonical preimage and
-- verified by the SDK before acting, so a forged or altered row is a no-op
-- (fail-safe). version is monotonic per scope (anti-rollback). Tenant-scoped and
-- row-level-security isolated.

CREATE TABLE IF NOT EXISTS kill_switches (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id       TEXT NOT NULL DEFAULT '',
    build_hash   TEXT NOT NULL DEFAULT '',
    command      INT NOT NULL,
    version      BIGINT NOT NULL,
    issued_at_ms BIGINT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    signature    BYTEA NOT NULL,
    key_id       TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, app_id, build_hash)
);

CREATE INDEX IF NOT EXISTS idx_killswitch_tenant ON kill_switches (tenant_id);

ALTER TABLE kill_switches ENABLE ROW LEVEL SECURITY;
ALTER TABLE kill_switches FORCE ROW LEVEL SECURITY;
CREATE POLICY killswitch_tenant_isolation ON kill_switches
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
