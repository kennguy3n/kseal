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
  description = "Redis engine version (major 7)."
  type        = string
  default     = "7.1"
  validation {
    condition     = can(regex("^7\\.", var.engine_version))
    error_message = "kseal targets Redis 7; engine_version must start with '7.'."
  }
}

variable "node_type" {
  description = "ElastiCache node type."
  type        = string
  default     = "cache.r6g.large"
}

variable "replicas_per_node_group" {
  description = "Read replicas per shard (>=1 for automatic failover)."
  type        = number
  default     = 1
}

variable "num_node_groups" {
  description = "Number of shards (1 = non-clustered)."
  type        = number
  default     = 1
}

variable "vpc_id" {
  description = "VPC the cache lives in."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnet IDs for the cache subnet group (>= 2 AZs)."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Provide at least two subnets across AZs for high availability."
  }
}

variable "allowed_security_group_ids" {
  description = "Security groups allowed to reach Redis on 6379 (the kseal node/pod SG)."
  type        = list(string)
  default     = []
}

variable "allowed_cidr_blocks" {
  description = "Extra CIDRs allowed to reach Redis on 6379."
  type        = list(string)
  default     = []
}

variable "kms_key_arn" {
  description = "KMS key for at-rest encryption. Empty = AWS-managed key."
  type        = string
  default     = ""
}

variable "snapshot_retention_days" {
  description = "Daily snapshot retention (0 disables)."
  type        = number
  default     = 7
}

# NOTE: the current kseal server (server/shared/config) connects to Redis with a
# host:port address only — no TLS handshake and no AUTH token. Enabling these
# requires a server enhancement (KSEAL_REDIS_TLS / KSEAL_REDIS_PASSWORD). They
# default off so the provisioned cache is usable by the server as-is; flip them
# on once the server supports it. Tracked in docs/deployment.md.
variable "transit_encryption_enabled" {
  description = "Enable in-transit (TLS) encryption. Requires server TLS support."
  type        = bool
  default     = false
}

variable "auth_enabled" {
  description = "Require an AUTH token. Requires server password support and transit encryption."
  type        = bool
  default     = false
}
