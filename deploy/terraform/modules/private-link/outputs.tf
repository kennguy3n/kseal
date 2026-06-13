output "nlb_arn" {
  description = "ARN of the internal NLB fronting the kseal server."
  value       = aws_lb.this.arn
}

output "target_group_arn" {
  description = "Target group ARN. Bind server pods to it with a TargetGroupBinding (aws-load-balancer-controller)."
  value       = aws_lb_target_group.this.arn
}

output "endpoint_service_name" {
  description = "VPC Endpoint Service name tenants use to create their interface VPC endpoint (e.g. com.amazonaws.vpce.<region>.vpce-svc-xxxx)."
  value       = aws_vpc_endpoint_service.this.service_name
}

output "endpoint_service_id" {
  description = "VPC Endpoint Service ID."
  value       = aws_vpc_endpoint_service.this.id
}

output "private_dns_name_verification" {
  description = "TXT record name/value to publish for private-DNS domain verification (empty when private DNS is disabled)."
  value = var.enable_private_dns ? {
    for c in aws_vpc_endpoint_service.this.private_dns_name_configuration :
    c.name => c.value
  } : {}
}

output "allowed_principals" {
  description = "Principals currently whitelisted to connect."
  value       = sort(var.allowed_principals)
}
