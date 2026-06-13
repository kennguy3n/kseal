variable "region" {
  description = "AWS region."
  type        = string
}

variable "name" {
  description = "Resource name prefix."
  type        = string
  default     = "kseal-dev"
}

variable "vpc_id" {
  description = "Existing VPC ID for the managed data stores."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs (>= 2 AZs) for Postgres + Redis."
  type        = list(string)
}

variable "workload_security_group_id" {
  description = "Security group attached to the kseal nodes/pods, granted DB + Redis access."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for storage + secret encryption (empty = AWS-managed keys)."
  type        = string
  default     = ""
}

variable "oidc_provider_arn" {
  description = "EKS IAM OIDC provider ARN (for External Secrets IRSA)."
  type        = string
}

variable "oidc_provider_url" {
  description = "EKS IAM OIDC provider URL without scheme."
  type        = string
}

variable "artifacts_bucket_name" {
  description = "Globally-unique S3 bucket name for kseal artifacts."
  type        = string
}

variable "kek" {
  description = "Base64-encoded 32-byte KSEAL_KEK. Pass via TF_VAR_kek or -var; never commit."
  type        = string
  sensitive   = true
}
