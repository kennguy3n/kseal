output "bootstrap_brokers" {
  description = "KSEAL_KAFKA_BROKERS value (IAM SASL bootstrap broker list)."
  value       = aws_msk_serverless_cluster.this.bootstrap_brokers_sasl_iam
}

output "cluster_arn" {
  description = "ARN of the MSK Serverless cluster."
  value       = aws_msk_serverless_cluster.this.arn
}

output "security_group_id" {
  description = "Security group protecting the broker."
  value       = aws_security_group.this.id
}
