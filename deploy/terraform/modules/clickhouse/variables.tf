variable "name" {
  description = "Resource name prefix (e.g. kseal-prod)."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "VPC the analytics store is reached from."
  type        = string
}

variable "allowed_security_group_ids" {
  description = "Security groups (the kseal workloads) allowed to reach ClickHouse."
  type        = list(string)
  default     = []
}

variable "allowed_cidr_blocks" {
  description = "Extra CIDRs allowed to reach ClickHouse (use sparingly)."
  type        = list(string)
  default     = []
}

variable "native_port" {
  description = "ClickHouse native-protocol port the server connects on (9440 for TLS, 9000 plaintext in-VPC)."
  type        = number
  default     = 9440
}

# ClickHouse has no first-party AWS managed service. In production the cluster is
# ClickHouse Cloud (reached over PrivateLink) or self-managed in-VPC; either way
# this module owns the access boundary and surfaces the connection address the
# server uses (KSEAL_CLICKHOUSE_ADDR). The endpoint host is provided here.
variable "endpoint_host" {
  description = "ClickHouse endpoint host (ClickHouse Cloud PrivateLink DNS or in-VPC service address)."
  type        = string
  validation {
    # This module is only instantiated when data_plane_clickhouse_enabled is
    # true, so a blank host is always a misconfiguration. Fail at plan time
    # rather than emitting a ":port" address the server can't dial.
    condition     = trimspace(var.endpoint_host) != ""
    error_message = "endpoint_host must be set when the ClickHouse module is enabled (set clickhouse_endpoint_host)."
  }
}
