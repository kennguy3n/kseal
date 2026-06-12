-- Signing keys are per-tenant Ed25519 key pairs used to sign trust tokens and
-- config bundles. Private key material is stored AES-256-GCM encrypted at rest
-- (envelope encryption under the server KEK). At most one key is active per
-- tenant; rotation deactivates the old key and inserts a new active one.

CREATE TABLE IF NOT EXISTS signing_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    algorithm       TEXT NOT NULL DEFAULT 'ed25519',
    public_key      BYTEA NOT NULL,
    private_key_enc BYTEA NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_signing_keys_tenant ON signing_keys (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_signing_keys_active
    ON signing_keys (tenant_id) WHERE is_active;

ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY signing_keys_tenant_isolation ON signing_keys
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
