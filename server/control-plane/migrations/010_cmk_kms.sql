-- Customer-managed keys (BYOK/CMK). A tenant with a non-null cmk_kms_uri has its
-- signing-key and webhook secret DEKs wrapped by the customer's own KMS key
-- identified by this URI; tenants with NULL fall back to the platform KEK. The
-- column lives on the admin-scoped tenants table (no RLS) alongside the other
-- tenant lifecycle fields.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS cmk_kms_uri TEXT;
