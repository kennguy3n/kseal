output "region" {
  description = "AWS region of this stack."
  value       = var.region
}

output "role" {
  description = "Topology role (primary|replica)."
  value       = var.role
}

output "postgres_instance_arn" {
  description = "ARN of this region's Postgres node (used as the replication source by replica regions)."
  value       = local.is_primary ? one(aws_db_instance.primary[*].arn) : one(aws_db_instance.replica[*].arn)
}

output "postgres_address" {
  description = "Hostname of this region's Postgres node."
  value       = local.is_primary ? one(aws_db_instance.primary[*].address) : one(aws_db_instance.replica[*].address)
}

output "postgres_port" {
  description = "Postgres port."
  value       = local.is_primary ? one(aws_db_instance.primary[*].port) : one(aws_db_instance.replica[*].port)
}

output "postgres_security_group_id" {
  description = "Security group protecting this region's Postgres node."
  value       = aws_security_group.pg.id
}

output "master_password" {
  description = "Generated master password (primary only; empty on replicas)."
  sensitive   = true
  value       = local.is_primary ? one(random_password.master[*].result) : ""
}

output "dsn" {
  description = "KSEAL_POSTGRES_DSN for this region (sslmode=require). Empty on replicas (read-only; no managed credentials)."
  sensitive   = true
  value = local.is_primary ? format(
    "postgres://%s:%s@%s:%d/%s?sslmode=require",
    urlencode(var.master_username),
    urlencode(one(random_password.master[*].result)),
    one(aws_db_instance.primary[*].address),
    one(aws_db_instance.primary[*].port),
    var.db_name,
  ) : ""
}

output "analytics_bucket_arn" {
  description = "ARN of this region's analytics cold-tier bucket (replication destination for replica regions)."
  value       = aws_s3_bucket.analytics.arn
}

output "analytics_bucket_name" {
  description = "Name of this region's analytics cold-tier bucket."
  value       = aws_s3_bucket.analytics.bucket
}

output "analytics_bucket_id" {
  description = "ID of this region's analytics cold-tier bucket (replication-configuration target)."
  value       = aws_s3_bucket.analytics.id
}

output "kms_key_arn" {
  description = "KMS key ARN protecting this region's data stores (empty when AWS-managed)."
  value       = var.kms_key_arn
}

output "regional_endpoint_hostname" {
  description = "Public hostname clients in/near this region should target. Empty when not set."
  value       = var.regional_endpoint_hostname
}
