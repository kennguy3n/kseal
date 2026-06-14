locals {
  tags = {
    "app.kubernetes.io/part-of" = "kseal"
    environment                 = "prod"
    managed-by                  = "terraform"
  }
}

module "postgres" {
  source = "../../modules/postgres"

  name           = var.name
  tags           = local.tags
  engine_version = "16.4"
  instance_class = "db.r6g.xlarge"

  allocated_storage     = 200
  max_allocated_storage = 2000

  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = [var.workload_security_group_id]

  multi_az              = true
  backup_retention_days = 30
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
  replicas_per_node_group = 2

  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = [var.workload_security_group_id]

  snapshot_retention_days = 14
  kms_key_arn             = var.kms_key_arn
  # transit_encryption_enabled / auth_enabled stay off until the server gains
  # Redis TLS + AUTH support (see modules/redis/variables.tf and docs/deployment.md).
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
  secret_prefix = "kseal/prod"
  kms_key_arn   = var.kms_key_arn

  kek          = var.kek
  postgres_dsn = module.postgres.dsn
  redis_addr   = module.redis.addr

  oidc_provider_arn = var.oidc_provider_arn
  oidc_provider_url = var.oidc_provider_url
}

# --- WS-Q production data plane (default-off) --------------------------------
# Kafka (MSK Serverless) broker for the telemetry pipeline. Created only when
# data_plane_kafka_enabled = true; uses IAM auth (no SASL password to store).
module "kafka" {
  source = "../../modules/kafka"
  count  = var.data_plane_kafka_enabled ? 1 : 0

  name = var.name
  tags = local.tags

  vpc_id                     = var.vpc_id
  subnet_ids                 = var.private_subnet_ids
  allowed_security_group_ids = [var.workload_security_group_id]
}

# ClickHouse analytics-store access boundary. Created only when
# data_plane_clickhouse_enabled = true; the cluster itself is ClickHouse Cloud
# (PrivateLink) or self-managed in-VPC, addressed by clickhouse_endpoint_host.
module "clickhouse" {
  source = "../../modules/clickhouse"
  count  = var.data_plane_clickhouse_enabled ? 1 : 0

  name = var.name
  tags = local.tags

  vpc_id                     = var.vpc_id
  allowed_security_group_ids = [var.workload_security_group_id]
  endpoint_host              = var.clickhouse_endpoint_host
}
