-- Trigram indexes backing RegistryService.SearchApps so a case-insensitive
-- substring match (LIKE '%q%') over an app's name or package id stays fast as
-- the per-tenant app count grows. RLS still scopes every query to one tenant;
-- these indexes accelerate the substring predicate within that tenant.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_apps_name_trgm
    ON apps USING gin (lower(name) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_apps_package_id_trgm
    ON apps USING gin (lower(package_id) gin_trgm_ops);
