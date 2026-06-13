-- Dedicated / regulated isolation tier. A tenant with dedicated_isolation = true
-- gets a dedicated cryptographic key domain: its secret material is sealed under
-- a per-tenant key derived (HKDF-SHA256) from the platform KEK, so a single
-- compromised ciphertext or derived key cannot cross tenant boundaries. Tenants
-- with the default (false) keep shared logical isolation under the platform KEK,
-- unchanged. The flag lives on the admin-scoped tenants table (no RLS) and is
-- tenant-configurable; it is independent of the tier label but typically set for
-- `regulated` tenants.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS dedicated_isolation BOOLEAN NOT NULL DEFAULT false;
