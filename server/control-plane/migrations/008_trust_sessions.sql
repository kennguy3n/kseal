-- Trust sessions record minted trust tokens so the data plane can validate
-- per-request proofs: it holds the session secret (derived from the issued
-- token) for proof verification, the monotonic sequence high-water mark for
-- anti-replay, and the bound identity (app, build, instance, policy, risk).

CREATE TABLE IF NOT EXISTS trust_sessions (
    token_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id           TEXT NOT NULL DEFAULT '',
    build_hash       TEXT NOT NULL DEFAULT '',
    instance_id      TEXT NOT NULL DEFAULT '',
    policy_hash      TEXT NOT NULL DEFAULT '',
    risk_level       INT NOT NULL DEFAULT 0,
    capability_scope TEXT[] NOT NULL DEFAULT '{}',
    session_secret   BYTEA NOT NULL,
    last_sequence    BIGINT NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active', 'revoked')),
    issued_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_trust_sessions_tenant ON trust_sessions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_trust_sessions_expiry ON trust_sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_trust_sessions_instance ON trust_sessions (tenant_id, instance_id);

ALTER TABLE trust_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust_sessions FORCE ROW LEVEL SECURITY;
-- Proof validation locates a session by token_id before the tenant is known, so
-- it runs under the admin bypass; tenant-scoped reads use the isolation policy.
CREATE POLICY trust_sessions_tenant_isolation ON trust_sessions
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
