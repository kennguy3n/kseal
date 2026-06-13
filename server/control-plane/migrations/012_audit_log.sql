-- Append-only, hash-chained audit trail of control-plane mutations. Each event
-- carries a per-tenant monotonic sequence and a SHA-256 hash that commits to the
-- previous event's hash, so any insertion, edit, or reordering breaks the chain
-- and is detected by VerifyAuditChain. Events carry only coarse, non-PII
-- attributes. The table is tenant-scoped and row-level-security isolated.

CREATE TABLE IF NOT EXISTS audit_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    seq           BIGINT NOT NULL,
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id   TEXT NOT NULL DEFAULT '',
    actor_key_id  TEXT NOT NULL DEFAULT '',
    metadata      JSONB NOT NULL DEFAULT '{}',
    prev_hash     TEXT NOT NULL DEFAULT '',
    hash          TEXT NOT NULL,
    -- created_at_ms is the exact unix-millis value committed to by the hash;
    -- created_at is a convenience timestamp for operators.
    created_at_ms BIGINT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_seq ON audit_events (tenant_id, seq DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_action ON audit_events (tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events (tenant_id, created_at_ms DESC);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_tenant_isolation ON audit_events
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));

-- Enforce append-only at the database layer: reject any UPDATE or DELETE unless
-- explicitly running in the privileged bypass context (admin maintenance /
-- tenant offboarding cascade). This makes the chain tamper-evident even against
-- a compromised application path.
CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger AS $$
BEGIN
    IF current_setting('app.bypass_rls', true) = 'on' THEN
        RETURN COALESCE(NEW, OLD);
    END IF;
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_append_only ON audit_events;
CREATE TRIGGER trg_audit_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
