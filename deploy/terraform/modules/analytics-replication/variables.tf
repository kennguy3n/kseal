variable "name" {
  description = "Resource name prefix (e.g. kseal-prod). The IAM replication role is named <name>-analytics-repl."
  type        = string
}

variable "tags" {
  description = "Tags applied to the IAM role."
  type        = map(string)
  default     = {}
}

variable "source_bucket_id" {
  description = "ID (name) of the source analytics bucket (the primary region's bucket) the replication configuration attaches to."
  type        = string
}

variable "source_bucket_arn" {
  description = "ARN of the source analytics bucket."
  type        = string
}

variable "source_kms_key_arn" {
  description = "KMS key ARN encrypting source objects (empty when the source uses SSE-S3 / AES256)."
  type        = string
  default     = ""
}

variable "destinations" {
  description = <<-EOT
    Replica-region analytics buckets to fan out to, keyed by region. Each entry
    needs the destination bucket ARN and the destination-region KMS key ARN
    (empty if the destination uses SSE-S3). Buckets must have versioning on.
  EOT
  type = map(object({
    bucket_arn  = string
    kms_key_arn = optional(string, "")
  }))
  validation {
    condition     = length(var.destinations) >= 1
    error_message = "Provide at least one replication destination."
  }
}
