-- Machine-readable data-processing registry: what data each app/SDK processes
-- (categories, purpose, retention, legal basis). Backs the compliance console
-- and store-disclosure tooling. One record per (tenant, app scope); an empty
-- app_id is a tenant-wide default. Tenant-scoped and row-level-security isolated.

CREATE TABLE IF NOT EXISTS data_processing_records (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    app_id              TEXT NOT NULL DEFAULT '',
    data_categories     TEXT[] NOT NULL DEFAULT '{}',
    purpose             TEXT NOT NULL DEFAULT '',
    retention_days      INT NOT NULL DEFAULT 0,
    legal_basis         TEXT NOT NULL DEFAULT '',
    third_party_sharing BOOLEAN NOT NULL DEFAULT false,
    updated_at_ms       BIGINT NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, app_id)
);

CREATE INDEX IF NOT EXISTS idx_dataproc_tenant ON data_processing_records (tenant_id);

ALTER TABLE data_processing_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE data_processing_records FORCE ROW LEVEL SECURITY;
CREATE POLICY dataproc_tenant_isolation ON data_processing_records
    USING (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true))
    WITH CHECK (current_setting('app.bypass_rls', true) = 'on'
           OR tenant_id::text = current_setting('app.tenant_id', true));
