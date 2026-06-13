output "zone_id" {
  description = "Route53 hosted zone ID records were created in."
  value       = local.zone_id
}

output "global_hostname" {
  description = "The global hostname clients target."
  value       = var.global_hostname
}

output "health_check_ids" {
  description = "Per-region Route53 health check IDs (empty when health checks are disabled)."
  value       = { for r, hc in aws_route53_health_check.regional : r => hc.id }
}

output "tenant_region_pins_ssm_name" {
  description = "SSM parameter name holding the tenant region-pin map (JSON)."
  value       = aws_ssm_parameter.tenant_region_pins.name
}

output "tenant_region_pins_ssm_arn" {
  description = "SSM parameter ARN holding the tenant region-pin map (grant the control plane ssm:GetParameter on this)."
  value       = aws_ssm_parameter.tenant_region_pins.arn
}
