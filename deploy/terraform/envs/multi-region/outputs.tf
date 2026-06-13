output "primary_postgres_address" {
  description = "Primary (writable) Postgres hostname."
  value       = module.primary.postgres_address
}

output "primary_dsn" {
  description = "KSEAL_POSTGRES_DSN for the primary region (write path)."
  sensitive   = true
  value       = module.primary.dsn
}

output "replica_postgres_addresses" {
  description = "Per-region read-replica Postgres hostnames (read path)."
  value = merge(
    local.enable_a ? { (var.replica_a_region) = module.replica_a[0].postgres_address } : {},
    local.enable_b ? { (var.replica_b_region) = module.replica_b[0].postgres_address } : {},
  )
}

output "analytics_buckets" {
  description = "Per-region analytics cold-tier bucket names."
  value = merge(
    { (var.primary_region) = module.primary.analytics_bucket_name },
    local.enable_a ? { (var.replica_a_region) = module.replica_a[0].analytics_bucket_name } : {},
    local.enable_b ? { (var.replica_b_region) = module.replica_b[0].analytics_bucket_name } : {},
  )
}

output "global_hostname" {
  description = "Global hostname clients target."
  value       = module.global_routing.global_hostname
}

output "tenant_region_pins_ssm_name" {
  description = "SSM parameter holding the per-tenant region-pin map."
  value       = module.global_routing.tenant_region_pins_ssm_name
}

output "regional_health_check_ids" {
  description = "Per-region Route53 health check IDs."
  value       = module.global_routing.health_check_ids
}
