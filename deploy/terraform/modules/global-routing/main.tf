# Global edge routing for the multi-region kseal data plane.
#
# - Resolves a single global hostname to the nearest healthy regional endpoint
#   (latency routing, default) or steers by client geography for data residency
#   (geolocation routing).
# - Per-region Route53 health checks withdraw an unhealthy region automatically.
# - Publishes the per-tenant region-pin map as a JSON SSM parameter the
#   control-plane router consumes for Enterprise/Regulated region pinning.

locals {
  zone_id = var.hosted_zone_id != "" ? var.hosted_zone_id : one(aws_route53_zone.this[*].zone_id)

  use_latency     = var.routing_policy == "latency"
  use_geolocation = var.routing_policy == "geolocation"

  ssm_name = var.ssm_parameter_name != "" ? var.ssm_parameter_name : "/kseal/${var.name}/tenant-region-pins"
}

resource "aws_route53_zone" "this" {
  count = var.hosted_zone_id == "" ? 1 : 0
  name  = var.domain_name
  tags  = var.tags
}

# Validate routing inputs that can't be expressed as static variable validation
# (they reference other variables).
resource "terraform_data" "routing_guard" {
  lifecycle {
    precondition {
      condition     = var.hosted_zone_id != "" || var.domain_name != ""
      error_message = "Set either hosted_zone_id (use an existing zone) or domain_name (create a new zone)."
    }
    precondition {
      condition     = !local.use_geolocation || contains(keys(var.regional_endpoints), var.default_region)
      error_message = "default_region must be one of regional_endpoints when routing_policy = 'geolocation'."
    }
    precondition {
      condition     = !local.use_geolocation || alltrue([for g in var.geolocation_routes : contains(keys(var.regional_endpoints), g.region)])
      error_message = "every geolocation_routes[*].region must be a key in regional_endpoints."
    }
  }
}

# ---------------------------------------------------------------------------
# Per-region health checks (optional). Bound to the latency records below so an
# unhealthy region is removed from DNS rotation within a few probe intervals.
# ---------------------------------------------------------------------------

resource "aws_route53_health_check" "regional" {
  for_each = var.enable_health_checks ? var.regional_endpoints : {}

  type              = "HTTPS"
  fqdn              = each.value.target
  port              = var.health_check_port
  resource_path     = var.health_check_path
  failure_threshold = 3
  request_interval  = 30

  tags = merge(var.tags, {
    Name                            = "${var.name}-${each.key}"
    "topology.kubernetes.io/region" = each.key
  })
}

# ---------------------------------------------------------------------------
# Latency routing (default): one record set per region under the global host.
# ---------------------------------------------------------------------------

resource "aws_route53_record" "latency" {
  for_each = local.use_latency ? var.regional_endpoints : {}

  zone_id        = local.zone_id
  name           = var.global_hostname
  type           = "CNAME"
  ttl            = var.record_ttl
  set_identifier = each.key
  records        = [each.value.target]

  latency_routing_policy {
    region = each.key
  }

  health_check_id = var.enable_health_checks ? aws_route53_health_check.regional[each.key].id : null
}

# ---------------------------------------------------------------------------
# Geolocation routing (data residency): one record per steered continent plus a
# default record for everything else.
# ---------------------------------------------------------------------------

resource "aws_route53_record" "geo" {
  for_each = local.use_geolocation ? { for g in var.geolocation_routes : g.continent => g } : {}

  zone_id        = local.zone_id
  name           = var.global_hostname
  type           = "CNAME"
  ttl            = var.record_ttl
  set_identifier = "geo-${each.key}"
  records        = [var.regional_endpoints[each.value.region].target]

  geolocation_routing_policy {
    continent = each.key
  }

  health_check_id = var.enable_health_checks ? aws_route53_health_check.regional[each.value.region].id : null
}

resource "aws_route53_record" "geo_default" {
  count = local.use_geolocation ? 1 : 0

  zone_id        = local.zone_id
  name           = var.global_hostname
  type           = "CNAME"
  ttl            = var.record_ttl
  set_identifier = "geo-default"
  records        = [var.regional_endpoints[var.default_region].target]

  geolocation_routing_policy {
    country = "*"
  }

  health_check_id = var.enable_health_checks ? aws_route53_health_check.regional[var.default_region].id : null
}

# ---------------------------------------------------------------------------
# Per-tenant region pinning, consumed by the control-plane router.
# ---------------------------------------------------------------------------

resource "aws_ssm_parameter" "tenant_region_pins" {
  name        = local.ssm_name
  description = "kseal per-tenant region pins (tenant_id => AWS region) for control-plane routing."
  type        = "String"
  tier        = "Intelligent-Tiering"
  value       = jsonencode(var.tenant_region_pins)
  tags        = var.tags
}
