variable "bucket_name" {
  description = "Globally-unique S3 bucket name (e.g. kseal-prod-artifacts)."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}

variable "kms_key_arn" {
  description = "KMS key for SSE-KMS. Empty uses SSE-S3 (AES256)."
  type        = string
  default     = ""
}

variable "versioning_enabled" {
  description = "Enable object versioning."
  type        = bool
  default     = true
}

variable "force_destroy" {
  description = "Allow deleting a non-empty bucket (keep false in prod)."
  type        = bool
  default     = false
}

variable "noncurrent_version_expiration_days" {
  description = "Expire noncurrent object versions after N days (0 disables)."
  type        = number
  default     = 90
}

variable "abort_incomplete_multipart_days" {
  description = "Abort incomplete multipart uploads after N days."
  type        = number
  default     = 7
}
