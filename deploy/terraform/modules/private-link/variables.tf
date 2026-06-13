variable "name" {
  description = "Resource name prefix (e.g. kseal-prod-regulated)."
  type        = string
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}

variable "vpc_id" {
  description = "VPC hosting the internal NLB (the kseal data-plane VPC)."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnet IDs (>= 2 AZs) for the internal NLB."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Provide at least two private subnets across AZs."
  }
}

variable "target_port" {
  description = "Server container port the NLB forwards to (Connect RPC over h2c)."
  type        = number
  default     = 8080
}

variable "listener_port" {
  description = "TCP port the NLB listens on for PrivateLink consumers."
  type        = number
  default     = 443
}

variable "health_check_path" {
  description = "HTTP path the NLB target group health check probes on the traffic port."
  type        = string
  default     = "/readyz"
}

variable "tls_certificate_arn" {
  description = "ACM certificate ARN to terminate TLS at the NLB. Empty = raw TCP passthrough (the server speaks h2c; consumers reach it privately over the AWS backbone)."
  type        = string
  default     = ""
}

variable "cross_zone_enabled" {
  description = "Enable NLB cross-zone load balancing (smoother distribution; small inter-AZ cost)."
  type        = bool
  default     = true
}

variable "deletion_protection" {
  description = "Protect the NLB from accidental deletion."
  type        = bool
  default     = true
}

variable "acceptance_required" {
  description = "Require manual acceptance of each consumer endpoint-connection request (recommended for regulated tenants)."
  type        = bool
  default     = true
}

variable "allowed_principals" {
  description = <<-EOT
    AWS principal ARNs (tenant account roots or roles) permitted to create an
    interface VPC endpoint to this service, e.g.
    "arn:aws:iam::222233334444:root". Empty = no principal whitelisted yet
    (no consumer can connect until one is added).
  EOT
  type        = list(string)
  default     = []
}

variable "enable_private_dns" {
  description = "Set a verified private DNS name on the endpoint service so consumers resolve a stable hostname instead of the per-endpoint DNS name."
  type        = bool
  default     = false
}

variable "private_dns_name" {
  description = "Private DNS name to advertise (e.g. private.kseal.example.com). Requires domain-ownership verification via the emitted TXT record; see outputs."
  type        = string
  default     = ""
  # The "required when enable_private_dns" rule is cross-variable, so it is
  # enforced by a precondition on terraform_data.guard (see main.tf) rather than
  # a validation block — keeping required_version at the repo-wide >= 1.6.0 floor.
}
