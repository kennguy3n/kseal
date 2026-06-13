locals {
  tags = {
    "app.kubernetes.io/part-of" = "kseal"
    environment                 = "prod"
    managed-by                  = "terraform"
    topology                    = "multi-region"
  }

  enable_a = var.replica_a_region != ""
  enable_b = var.replica_b_region != ""

  # Regional edge endpoints behind the global hostname.
  regional_endpoints = merge(
    { (var.primary_region) = { target = var.primary.endpoint_hostname } },
    local.enable_a ? { (var.replica_a_region) = { target = var.replica_a.endpoint_hostname } } : {},
    local.enable_b ? { (var.replica_b_region) = { target = var.replica_b.endpoint_hostname } } : {},
  )

  # Analytics replication destinations (primary -> each enabled replica).
  analytics_destinations = merge(
    local.enable_a ? {
      (var.replica_a_region) = {
        bucket_arn  = module.replica_a[0].analytics_bucket_arn
        kms_key_arn = var.replica_a.kms_key_arn
      }
    } : {},
    local.enable_b ? {
      (var.replica_b_region) = {
        bucket_arn  = module.replica_b[0].analytics_bucket_arn
        kms_key_arn = var.replica_b.kms_key_arn
      }
    } : {},
  )
}

# ---------------------------------------------------------------------------
# Primary region (writable Postgres + analytics source).
# ---------------------------------------------------------------------------
module "primary" {
  source = "../../modules/multi-region"
  providers = {
    aws = aws
  }

  name           = var.name
  region         = var.primary_region
  role           = "primary"
  tags           = local.tags
  instance_class = var.instance_class
  multi_az       = var.multi_az

  vpc_id                     = var.primary.vpc_id
  subnet_ids                 = var.primary.private_subnet_ids
  allowed_security_group_ids = [var.primary.workload_security_group_id]
  kms_key_arn                = var.primary.kms_key_arn
  deletion_protection        = var.deletion_protection

  analytics_bucket_name      = var.primary.analytics_bucket_name
  regional_endpoint_hostname = var.primary.endpoint_hostname
}

# ---------------------------------------------------------------------------
# Replica region A (cross-region read replica + analytics replication target).
# ---------------------------------------------------------------------------
module "replica_a" {
  count  = local.enable_a ? 1 : 0
  source = "../../modules/multi-region"
  providers = {
    aws = aws.replica_a
  }

  name           = var.name
  region         = var.replica_a_region
  role           = "replica"
  tags           = local.tags
  instance_class = var.instance_class

  vpc_id                     = var.replica_a.vpc_id
  subnet_ids                 = var.replica_a.private_subnet_ids
  allowed_security_group_ids = [var.replica_a.workload_security_group_id]
  kms_key_arn                = var.replica_a.kms_key_arn
  deletion_protection        = var.deletion_protection
  source_db_arn              = module.primary.postgres_instance_arn

  analytics_bucket_name      = var.replica_a.analytics_bucket_name
  regional_endpoint_hostname = var.replica_a.endpoint_hostname
}

# ---------------------------------------------------------------------------
# Replica region B.
# ---------------------------------------------------------------------------
module "replica_b" {
  count  = local.enable_b ? 1 : 0
  source = "../../modules/multi-region"
  providers = {
    aws = aws.replica_b
  }

  name           = var.name
  region         = var.replica_b_region
  role           = "replica"
  tags           = local.tags
  instance_class = var.instance_class

  vpc_id                     = var.replica_b.vpc_id
  subnet_ids                 = var.replica_b.private_subnet_ids
  allowed_security_group_ids = [var.replica_b.workload_security_group_id]
  kms_key_arn                = var.replica_b.kms_key_arn
  deletion_protection        = var.deletion_protection
  source_db_arn              = module.primary.postgres_instance_arn

  analytics_bucket_name      = var.replica_b.analytics_bucket_name
  regional_endpoint_hostname = var.replica_b.endpoint_hostname
}

# ---------------------------------------------------------------------------
# Cross-region analytics replication (primary bucket -> replica buckets).
# Lives at the env level so it can depend on both the primary and the replica
# buckets without forming a module-level cycle.
# ---------------------------------------------------------------------------
module "analytics_replication" {
  count  = length(local.analytics_destinations) > 0 ? 1 : 0
  source = "../../modules/analytics-replication"
  providers = {
    aws = aws
  }

  name               = var.name
  tags               = local.tags
  source_bucket_id   = module.primary.analytics_bucket_id
  source_bucket_arn  = module.primary.analytics_bucket_arn
  source_kms_key_arn = var.primary.kms_key_arn
  destinations       = local.analytics_destinations
}

# ---------------------------------------------------------------------------
# Global edge routing + per-tenant region pinning.
# ---------------------------------------------------------------------------
module "global_routing" {
  source = "../../modules/global-routing"
  providers = {
    aws = aws
  }

  name               = var.name
  tags               = local.tags
  hosted_zone_id     = var.hosted_zone_id
  domain_name        = var.domain_name
  global_hostname    = var.global_hostname
  regional_endpoints = local.regional_endpoints

  routing_policy       = var.routing_policy
  default_region       = var.primary_region
  geolocation_routes   = var.geolocation_routes
  tenant_region_pins   = var.tenant_region_pins
  enable_health_checks = var.enable_health_checks
}
