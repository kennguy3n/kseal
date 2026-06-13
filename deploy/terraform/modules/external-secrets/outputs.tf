output "secret_arns" {
  description = "ARNs of the created Secrets Manager secrets."
  value       = { for k, s in aws_secretsmanager_secret.this : k => s.arn }
}

output "irsa_role_arn" {
  description = "IAM role ARN for the External Secrets Operator service account (annotate the SA with this)."
  value       = aws_iam_role.eso.arn
}

output "read_policy_arn" {
  description = "ARN of the scoped read policy."
  value       = aws_iam_policy.read.arn
}
