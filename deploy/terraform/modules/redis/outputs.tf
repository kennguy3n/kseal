output "primary_endpoint" {
  description = "Primary endpoint host."
  value       = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "reader_endpoint" {
  description = "Reader endpoint host."
  value       = aws_elasticache_replication_group.this.reader_endpoint_address
}

output "port" {
  description = "Redis port."
  value       = aws_elasticache_replication_group.this.port
}

output "addr" {
  description = "KSEAL_REDIS_ADDR value (host:port)."
  value       = format("%s:%d", aws_elasticache_replication_group.this.primary_endpoint_address, aws_elasticache_replication_group.this.port)
}

output "security_group_id" {
  description = "Security group protecting the cache."
  value       = aws_security_group.this.id
}

output "auth_token" {
  description = "AUTH token (empty unless auth_enabled + transit encryption)."
  sensitive   = true
  value       = var.auth_enabled && var.transit_encryption_enabled ? random_password.auth.result : ""
}
