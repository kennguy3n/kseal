output "addr" {
  description = "KSEAL_CLICKHOUSE_ADDR value (host:port)."
  value       = format("%s:%d", var.endpoint_host, var.native_port)
}

output "security_group_id" {
  description = "Security group protecting the analytics store."
  value       = aws_security_group.this.id
}
