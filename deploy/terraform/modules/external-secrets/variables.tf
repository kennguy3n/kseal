variable "name" {
  description = "Resource name prefix (e.g. kseal-prod)."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}

variable "secret_prefix" {
  description = "Secrets Manager path prefix (matches Helm externalSecrets.remoteKeys, e.g. kseal/prod)."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for Secrets Manager encryption. Empty = AWS-managed key."
  type        = string
  default     = ""
}

variable "kek" {
  description = "Base64-encoded 32-byte KSEAL_KEK. Generate out-of-band; never commit."
  type        = string
  sensitive   = true
}

variable "postgres_dsn" {
  description = "KSEAL_POSTGRES_DSN connection string (from the postgres module output)."
  type        = string
  sensitive   = true
}

variable "redis_addr" {
  description = "KSEAL_REDIS_ADDR (host:port, from the redis module output)."
  type        = string
}

variable "oidc_provider_arn" {
  description = "EKS cluster IAM OIDC provider ARN (for IRSA)."
  type        = string
}

variable "oidc_provider_url" {
  description = "EKS cluster IAM OIDC provider URL without scheme (e.g. oidc.eks.us-east-1.amazonaws.com/id/XXXX)."
  type        = string
}

variable "external_secrets_namespace" {
  description = "Namespace the External Secrets Operator runs in."
  type        = string
  default     = "external-secrets"
}

variable "external_secrets_service_account" {
  description = "Service account the External Secrets Operator uses."
  type        = string
  default     = "external-secrets"
}

variable "recovery_window_days" {
  description = "Secrets Manager recovery window before permanent deletion."
  type        = number
  default     = 7
}
