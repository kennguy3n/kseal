-- Tenants are the primary isolation boundary. This table is admin-scoped (the
-- control plane manages tenants) and therefore is NOT row-level-security
-- restricted; tenant-scoped child tables are protected in later migrations.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    tier        TEXT NOT NULL DEFAULT 'starter'
                  CHECK (tier IN ('starter', 'growth', 'enterprise', 'regulated')),
    status      TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);
