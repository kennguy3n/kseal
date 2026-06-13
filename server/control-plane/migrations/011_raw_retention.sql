-- Per-tenant raw-telemetry retention window (privacy, Phase 4). When set, raw
-- events older than raw_retention_days are purged by the data plane while
-- derived/aggregate analytics are retained. NULL means "use the platform
-- default" (KSEAL_RAW_RETENTION_DAYS). Lives on the admin-scoped tenants table.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS raw_retention_days INTEGER
    CHECK (raw_retention_days IS NULL OR raw_retention_days >= 0);
