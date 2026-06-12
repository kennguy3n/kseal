-- API keys authenticate control-plane callers. Only the argon2id hash of the
-- secret is stored; the plaintext is shown once at creation. key_id is the
-- public, indexable identifier embedded in the presented key.

CREATE TABLE IF NOT EXISTS api_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_id        TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    secret_hash   TEXT NOT NULL,
    scopes        TEXT[] NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'revoked')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_id ON api_keys (key_id);

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
-- Validation looks up a key by key_id before any tenant is known, so it runs
-- under the admin bypass; all other access is tenant-scoped.
CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
