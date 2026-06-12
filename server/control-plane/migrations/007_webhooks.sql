-- Webhooks are tenant-registered HTTP endpoints that receive HMAC-signed event
-- deliveries. Each holds an encrypted HMAC signing secret; signing_key_id is the
-- public identifier sent in the signature header for rotation.

CREATE TABLE IF NOT EXISTS webhooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    event_types     INT[] NOT NULL DEFAULT '{}',
    signing_key_id  TEXT NOT NULL,
    secret_enc      BYTEA NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks (tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks (tenant_id, is_active);

ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks FORCE ROW LEVEL SECURITY;
CREATE POLICY webhooks_tenant_isolation ON webhooks
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
