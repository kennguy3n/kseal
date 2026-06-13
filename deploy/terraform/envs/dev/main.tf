locals {
  tags = {
    "app.kubernetes.io/part-of" = "kseal"
    environment                 = "dev"
    managed-by                  = "terraform"
  }
}

module "postgres" {
  source = "../../modules/postgres"

  name           = var.name
  tags           = local.tags
  engine_version = "16.4"
  instance_class = "db.t4g.medium"

  allocated_storage     = 20
  max_allocated_storage = 100

  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = [var.workload_security_group_id]

  # Dev: single AZ, short retention, allow teardown.
  multi_az              = false
  backup_retention_days = 3
  deletion_protection   = false
  kms_key_arn           = var.kms_key_arn
}

module "redis" {
  source = "../../modules/redis"

  name           = var.name
  tags           = local.tags
  engine_version = "7.1"
  node_type      = "cache.t4g.small"

  num_node_groups         = 1
  replicas_per_node_group = 0

  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = [var.workload_security_group_id]

  snapshot_retention_days = 0
  kms_key_arn             = var.kms_key_arn
}

module "object_store" {
  source = "../../modules/object-store"

  bucket_name        = var.artifacts_bucket_name
  tags               = local.tags
  kms_key_arn        = var.kms_key_arn
  versioning_enabled = false
  force_destroy      = true
}

module "external_secrets" {
  source = "../../modules/external-secrets"

  name          = var.name
  tags          = local.tags
  secret_prefix = "kseal/dev"
  kms_key_arn   = var.kms_key_arn

  kek          = var.kek
  postgres_dsn = module.postgres.dsn
  redis_addr   = module.redis.addr

  oidc_provider_arn    = var.oidc_provider_arn
  oidc_provider_url    = var.oidc_provider_url
  recovery_window_days = 0
}
