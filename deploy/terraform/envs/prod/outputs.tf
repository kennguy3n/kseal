output "postgres_address" {
  description = "Postgres hostname."
  value       = module.postgres.address
}

output "redis_addr" {
  description = "KSEAL_REDIS_ADDR (host:port)."
  value       = module.redis.addr
}

output "artifacts_bucket" {
  description = "Artifacts S3 bucket name."
  value       = module.object_store.bucket_name
}

output "external_secrets_irsa_role_arn" {
  description = "Annotate the External Secrets Operator service account with this role ARN."
  value       = module.external_secrets.irsa_role_arn
}

output "secret_arns" {
  description = "Secrets Manager ARNs backing the kseal server secrets."
  value       = module.external_secrets.secret_arns
}

output "kafka_bootstrap_brokers" {
  description = "KSEAL_KAFKA_BROKERS value (empty unless data_plane_kafka_enabled)."
  value       = var.data_plane_kafka_enabled ? module.kafka[0].bootstrap_brokers : ""
}

output "clickhouse_addr" {
  description = "KSEAL_CLICKHOUSE_ADDR value (empty unless data_plane_clickhouse_enabled)."
  value       = var.data_plane_clickhouse_enabled ? module.clickhouse[0].addr : ""
}
