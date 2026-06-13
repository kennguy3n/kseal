output "replication_role_arn" {
  description = "IAM role assumed by S3 to replicate analytics objects."
  value       = aws_iam_role.this.arn
}

output "destination_regions" {
  description = "Regions this configuration replicates analytics to."
  value       = local.dest_regions
}
