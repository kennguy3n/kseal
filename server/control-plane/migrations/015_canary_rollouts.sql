-- Canary rollout state for staged policy/config delivery. One rollout per
-- (tenant, app): a candidate policy served to `percent` of instances (by
-- deterministic instance-hash bucketing), with stable_policy_id as the
-- last-known-good to revert to. The auto-rollback controller writes block_rate
-- / sample_count and flips state to ROLLED_BACK when the guardrail threshold is
-- breached. Tenant-scoped and row-level-security isolated.

CREATE TABLE IF NOT EXISTS canary_rollouts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id              TEXT NOT NULL,
    candidate_policy_id TEXT NOT NULL,
    stable_policy_id    TEXT NOT NULL DEFAULT '',
    percent             INT NOT NULL DEFAULT 0 CHECK (percent BETWEEN 0 AND 100),
    -- 1=ACTIVE, 2=PROMOTED, 3=ROLLED_BACK (mirrors CanaryState).
    state               INT NOT NULL DEFAULT 1,
    block_rate          DOUBLE PRECISION NOT NULL DEFAULT 0,
    sample_count        BIGINT NOT NULL DEFAULT 0,
    rollback_threshold  DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_event          TEXT NOT NULL DEFAULT '',
    updated_at_ms       BIGINT NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, app_id)
);

CREATE INDEX IF NOT EXISTS idx_canary_tenant ON canary_rollouts (tenant_id);
CREATE INDEX IF NOT EXISTS idx_canary_active ON canary_rollouts (state) WHERE state = 1;

ALTER TABLE canary_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE canary_rollouts FORCE ROW LEVEL SECURITY;
CREATE POLICY canary_tenant_isolation ON canary_rollouts
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
