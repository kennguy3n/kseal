# Private connectivity for regulated tenants via AWS PrivateLink. An internal
# Network Load Balancer fronts the kseal server and is published as a VPC
# Endpoint Service; tenants reach kseal by creating an interface VPC endpoint in
# their own VPC. There is NO public ingress path: the NLB is internal and the
# endpoint service is private to whitelisted principals.
#
# Pod registration is dynamic and NoOps: the aws-load-balancer-controller binds
# server pod IPs to the target group via a TargetGroupBinding (see
# docs/deployment-private-link.md), so there are no static targets here.

locals {
  use_tls = var.tls_certificate_arn != ""
}

resource "aws_lb" "this" {
  name                             = "${var.name}-pl"
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = var.subnet_ids
  enable_cross_zone_load_balancing = var.cross_zone_enabled
  enable_deletion_protection       = var.deletion_protection
  tags                             = var.tags
}

resource "aws_lb_target_group" "this" {
  name        = "${var.name}-pl"
  port        = var.target_port
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  # L7 health check on the traffic port so only Ready server pods receive
  # connections.
  health_check {
    enabled             = true
    protocol            = "HTTP"
    path                = var.health_check_path
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    interval            = 10
    timeout             = 6
  }

  # Reset connections to deregistering pods promptly during rollouts.
  deregistration_delay = 30

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.this.arn
  port              = var.listener_port
  protocol          = local.use_tls ? "TLS" : "TCP"
  certificate_arn   = local.use_tls ? var.tls_certificate_arn : null
  ssl_policy        = local.use_tls ? "ELBSecurityPolicy-TLS13-1-2-2021-06" : null

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# VPC Endpoint Service (PrivateLink provider side).
# ---------------------------------------------------------------------------

resource "aws_vpc_endpoint_service" "this" {
  acceptance_required        = var.acceptance_required
  network_load_balancer_arns = [aws_lb.this.arn]
  private_dns_name           = var.enable_private_dns ? var.private_dns_name : null
  tags                       = merge(var.tags, { Name = "${var.name}-endpoint-service" })
}

# Whitelist consumer principals. Without an entry, no tenant can connect.
resource "aws_vpc_endpoint_service_allowed_principal" "this" {
  for_each = toset(var.allowed_principals)

  vpc_endpoint_service_id = aws_vpc_endpoint_service.this.id
  principal_arn           = each.value
}
