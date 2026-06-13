variable "name" {
  description = "Resource name prefix (e.g. kseal-prod)."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}

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
  description = "RDS instance class."
  type        = string
  default     = "db.r6g.large"
}

variable "allocated_storage" {
  description = "Initial storage in GiB."
  type        = number
  default     = 100
}

variable "max_allocated_storage" {
  description = "Storage autoscaling ceiling in GiB (0 disables autoscaling)."
  type        = number
  default     = 1000
}

variable "db_name" {
  description = "Initial database name."
  type        = string
  default     = "kseal"
}

variable "master_username" {
  description = "Master username."
  type        = string
  default     = "kseal"
}

variable "vpc_id" {
  description = "VPC the database lives in."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnet IDs for the DB subnet group (>= 2 AZs)."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Provide at least two subnets across AZs for high availability."
  }
}

variable "allowed_security_group_ids" {
  description = "Security groups allowed to reach Postgres on 5432 (the kseal node/pod SG)."
  type        = list(string)
  default     = []
}

variable "allowed_cidr_blocks" {
  description = "Extra CIDRs allowed to reach Postgres on 5432."
  type        = list(string)
  default     = []
}

variable "multi_az" {
  description = "Deploy a standby in a second AZ for automatic failover."
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Automated backup retention in days."
  type        = number
  default     = 14
}

variable "deletion_protection" {
  description = "Block accidental deletion of the instance."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "KMS key for storage + Performance Insights encryption. Empty = AWS-managed key."
  type        = string
  default     = ""
}

variable "performance_insights_enabled" {
  description = "Enable Performance Insights."
  type        = bool
  default     = true
}

variable "monitoring_role_arn" {
  description = "IAM role ARN for enhanced monitoring (empty disables)."
  type        = string
  default     = ""
}
