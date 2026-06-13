variable "name" {
  description = "Resource name prefix (e.g. kseal-prod)."
  type        = string
}

variable "region" {
  description = "AWS region this regional stack lives in (must match the aws provider passed by the caller)."
  type        = string
}

variable "role" {
  description = "Topology role of this region: 'primary' owns the writable Postgres + analytics source; 'replica' hosts a cross-region read replica + analytics replication target."
  type        = string
  default     = "primary"
  validation {
    condition     = contains(["primary", "replica"], var.role)
    error_message = "role must be 'primary' or 'replica'."
  }
}

variable "tags" {
  description = "Tags applied to every resource. A topology.kubernetes.io/region tag is merged in automatically."
  type        = map(string)
  default     = {}
}

# ---- networking ------------------------------------------------------------

variable "vpc_id" {
  description = "VPC (in this region) hosting the regional data stores."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnet IDs in this region (>= 2 AZs) for the Postgres subnet group."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Provide at least two subnets across AZs for high availability."
  }
}

variable "allowed_security_group_ids" {
  description = "Security groups (this region's kseal workloads) allowed to reach Postgres on 5432."
  type        = list(string)
  default     = []
}

# ---- postgres --------------------------------------------------------------

variable "engine_version" {
  description = "PostgreSQL engine version (major 16)."
  type        = string
  default     = "16.4"
  validation {
    condition     = can(regex("^16\\.", var.engine_version))
    error_message = "kseal targets PostgreSQL 16; engine_version must start with '16.'."
  }
}

variable "instance_class" {
  description = "RDS instance class for the regional node."
  type        = string
  default     = "db.r6g.large"
}

variable "allocated_storage" {
  description = "Initial storage in GiB (primary only; replicas inherit from the source)."
  type        = number
  default     = 100
}

variable "max_allocated_storage" {
  description = "Storage autoscaling ceiling in GiB (0 disables)."
  type        = number
  default     = 1000
}

variable "db_name" {
  description = "Initial database name (primary only)."
  type        = string
  default     = "kseal"
}

variable "master_username" {
  description = "Master username (primary only)."
  type        = string
  default     = "kseal"
}

variable "multi_az" {
  description = "Run a same-region standby for the primary (ignored for replicas)."
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Automated backup retention in days (primary)."
  type        = number
  default     = 14
}

variable "deletion_protection" {
  description = "Block accidental deletion of the regional Postgres node."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "KMS key (in THIS region) for storage encryption. Empty = AWS-managed key. Cross-region replicas require a key in the replica region."
  type        = string
  default     = ""
}

variable "source_db_arn" {
  description = "ARN of the primary Postgres instance to replicate from. Required when role = 'replica'; ignored for 'primary'."
  type        = string
  default     = ""
  validation {
    condition     = var.source_db_arn == "" || can(regex("^arn:aws", var.source_db_arn))
    error_message = "source_db_arn must be a valid AWS ARN when set."
  }
}

# ---- analytics cold tier (S3) ---------------------------------------------

variable "analytics_bucket_name" {
  description = "Globally-unique S3 bucket name for this region's analytics cold tier (telemetry aggregates, raw retention dumps)."
  type        = string
}

variable "analytics_force_destroy" {
  description = "Allow Terraform to delete a non-empty analytics bucket (dev/test only)."
  type        = bool
  default     = false
}

variable "analytics_noncurrent_version_expiration_days" {
  description = "Expire noncurrent analytics object versions after N days (0 disables)."
  type        = number
  default     = 30
}

# ---- routing ---------------------------------------------------------------

variable "regional_endpoint_hostname" {
  description = "Public hostname clients in/near this region should target (e.g. api.eu.kseal.example.com). Surfaced to outputs + Helm region overlays; routing records are created by the global-routing module."
  type        = string
  default     = ""
}
