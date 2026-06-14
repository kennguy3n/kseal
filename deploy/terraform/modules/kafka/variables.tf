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
  description = "VPC the broker lives in."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnet IDs for the MSK Serverless cluster (>= 2 AZs)."
  type        = list(string)
  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "Provide at least two subnets across AZs for high availability."
  }
}

variable "allowed_security_group_ids" {
  description = "Security groups (the kseal workloads) allowed to reach the broker."
  type        = list(string)
  default     = []
}

variable "allowed_cidr_blocks" {
  description = "Extra CIDRs allowed to reach the broker (use sparingly)."
  type        = list(string)
  default     = []
}
