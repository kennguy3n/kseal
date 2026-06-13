locals {
  tags = {
    "app.kubernetes.io/part-of" = "kseal"
    environment                 = "staging"
    managed-by                  = "terraform"
  }
}

module "postgres" {
  source = "../../modules/postgres"

  name           = var.name
  tags           = local.tags
  engine_version = "16.4"
  instance_class = "db.r6g.large"

  allocated_storage     = 100
  max_allocated_storage = 1000

  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = [var.workload_security_group_id]

  multi_az              = true
  backup_retention_days = 14
  deletion_protection   = true
  kms_key_arn           = var.kms_key_arn
}

module "redis" {
  source = "../../modules/redis"

  name           = var.name
  tags           = local.tags
  engine_version = "7.1"
  node_type      = "cache.r6g.large"

  num_node_groups         = 1
  replicas_per_node_group = 1

  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = [var.workload_security_group_id]

  snapshot_retention_days = 7
  kms_key_arn             = var.kms_key_arn
}

module "object_store" {
  source = "../../modules/object-store"

  bucket_name        = var.artifacts_bucket_name
  tags               = local.tags
  kms_key_arn        = var.kms_key_arn
  versioning_enabled = true
  force_destroy      = false
}

module "external_secrets" {
  source = "../../modules/external-secrets"

  name          = var.name
  tags          = local.tags
  secret_prefix = "kseal/staging"
  kms_key_arn   = var.kms_key_arn

  kek          = var.kek
  postgres_dsn = module.postgres.dsn
  redis_addr   = module.redis.addr

  oidc_provider_arn = var.oidc_provider_arn
  oidc_provider_url = var.oidc_provider_url
}
