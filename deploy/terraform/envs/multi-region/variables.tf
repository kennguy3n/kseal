variable "name" {
  description = "Resource name prefix."
  type        = string
  default     = "kseal-prod"
}

# ---- regions ---------------------------------------------------------------

variable "primary_region" {
  description = "Primary AWS region (writable Postgres + analytics source)."
  type        = string
}

variable "replica_a_region" {
  description = "First replica region. Empty disables it (single-region operation)."
  type        = string
  default     = ""
}

variable "replica_b_region" {
  description = "Second replica region. Empty disables it."
  type        = string
  default     = ""
}

# Per-region infrastructure inputs. Replica entries are only consumed when the
# matching *_region variable is set; defaults keep single-region plans valid.
variable "primary" {
  description = "Primary region networking + naming inputs."
  type = object({
    vpc_id                     = string
    private_subnet_ids         = list(string)
    workload_security_group_id = string
    kms_key_arn                = optional(string, "")
    analytics_bucket_name      = string
    endpoint_hostname          = string
  })
}

variable "replica_a" {
  description = "Replica A region networking + naming inputs (required when replica_a_region is set)."
  type = object({
    vpc_id                     = string
    private_subnet_ids         = list(string)
    workload_security_group_id = string
    kms_key_arn                = optional(string, "")
    analytics_bucket_name      = string
    endpoint_hostname          = string
  })
  default = {
    vpc_id                     = ""
    private_subnet_ids         = []
    workload_security_group_id = ""
    analytics_bucket_name      = ""
    endpoint_hostname          = ""
  }
}

variable "replica_b" {
  description = "Replica B region networking + naming inputs (required when replica_b_region is set)."
  type = object({
    vpc_id                     = string
    private_subnet_ids         = list(string)
    workload_security_group_id = string
    kms_key_arn                = optional(string, "")
    analytics_bucket_name      = string
    endpoint_hostname          = string
  })
  default = {
    vpc_id                     = ""
    private_subnet_ids         = []
    workload_security_group_id = ""
    analytics_bucket_name      = ""
    endpoint_hostname          = ""
  }
}

# ---- postgres sizing -------------------------------------------------------

variable "instance_class" {
  description = "RDS instance class for every regional node."
  type        = string
  default     = "db.r6g.large"
}

variable "multi_az" {
  description = "Same-region standby for the primary."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Block accidental deletion of regional Postgres nodes."
  type        = bool
  default     = true
}

# ---- global routing --------------------------------------------------------

variable "hosted_zone_id" {
  description = "Existing Route53 hosted zone ID. Empty creates a zone for domain_name."
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Apex domain for a zone to create when hosted_zone_id is empty."
  type        = string
  default     = ""
}

variable "global_hostname" {
  description = "Global hostname SDKs/devices target (resolved to the nearest healthy region)."
  type        = string
}

variable "routing_policy" {
  description = "Global routing policy: 'latency' (default edge) or 'geolocation' (data residency)."
  type        = string
  default     = "latency"
}

variable "geolocation_routes" {
  description = "Continent => region steering used when routing_policy = 'geolocation'."
  type = list(object({
    continent = string
    region    = string
  }))
  default = []
}

variable "tenant_region_pins" {
  description = "Per-tenant region pins (tenant_id => region) published to SSM for the control-plane router."
  type        = map(string)
  default     = {}
}

variable "enable_health_checks" {
  description = "Create per-region Route53 health checks for automatic failover."
  type        = bool
  default     = true
}
