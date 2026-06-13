variable "name" {
  description = "Resource name prefix (e.g. kseal-prod)."
  type        = string
}

variable "tags" {
  description = "Tags applied to taggable resources (Route53 health checks, SSM parameter)."
  type        = map(string)
  default     = {}
}

variable "hosted_zone_id" {
  description = "Existing Route53 hosted zone ID to manage records in. Leave empty to create a zone for domain_name."
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Apex domain for a zone to create when hosted_zone_id is empty (e.g. kseal.example.com)."
  type        = string
  default     = ""
  validation {
    condition     = var.hosted_zone_id != "" || var.domain_name != ""
    error_message = "Set either hosted_zone_id (use an existing zone) or domain_name (create a new zone)."
  }
}

variable "global_hostname" {
  description = "The single global hostname SDKs/devices target (e.g. api.kseal.example.com). Latency-based records resolve it to the nearest healthy regional endpoint."
  type        = string
}

variable "regional_endpoints" {
  description = <<-EOT
    Per-region edge endpoints behind the global hostname. Keyed by AWS region.
    `target` is the regional CNAME target (regional ingress/ALB hostname).
    Latency-based routing sends each client to the lowest-latency region.
  EOT
  type = map(object({
    target = string
  }))
  validation {
    condition     = length(var.regional_endpoints) >= 1
    error_message = "Provide at least one regional endpoint."
  }
}

variable "routing_policy" {
  description = <<-EOT
    Global routing policy for global_hostname:
      - "latency": send each client to the lowest-latency healthy region
        (default global edge).
      - "geolocation": steer by client continent for data residency, with a
        default record for unmatched locations (uses geolocation_routes +
        default_region). Route53 forbids mixing policies on one name+type, so
        this is an explicit choice rather than both at once.
  EOT
  type        = string
  default     = "latency"
  validation {
    condition     = contains(["latency", "geolocation"], var.routing_policy)
    error_message = "routing_policy must be 'latency' or 'geolocation'."
  }
}

variable "default_region" {
  description = "Region the geolocation default record points to (required when routing_policy = 'geolocation'). Must be a key in regional_endpoints."
  type        = string
  default     = ""
}

variable "record_ttl" {
  description = "TTL (seconds) for the latency/geolocation CNAME records."
  type        = number
  default     = 30
}

variable "enable_health_checks" {
  description = "Create a Route53 health check per regional endpoint and bind it to that region's latency record, so an unhealthy region is automatically withdrawn from rotation (failover)."
  type        = bool
  default     = true
}

variable "health_check_path" {
  description = "HTTPS path probed by the per-region health checks."
  type        = string
  default     = "/readyz"
}

variable "health_check_port" {
  description = "Port probed by the per-region health checks."
  type        = number
  default     = 443
}

variable "geolocation_routes" {
  description = <<-EOT
    Optional geolocation overrides layered on top of latency routing, used for
    data-residency steering (e.g. force EU clients onto the EU region). Each
    entry pins a continent to a region present in regional_endpoints.
  EOT
  type = list(object({
    continent = string # ISO continent code: AF, AN, AS, EU, OC, NA, SA
    region    = string # must be a key in regional_endpoints
  }))
  default = []
}

variable "tenant_region_pins" {
  description = <<-EOT
    Per-tenant region pinning (Enterprise/Regulated tiers): tenant_id => AWS
    region. Published as a single JSON SSM parameter the control-plane router
    reads to route a pinned tenant's traffic to its home region regardless of
    client geography. Empty map publishes an empty pin set.
  EOT
  type        = map(string)
  default     = {}
}

variable "ssm_parameter_name" {
  description = "Name of the SSM parameter holding the tenant region-pin map (JSON)."
  type        = string
  default     = ""
}
