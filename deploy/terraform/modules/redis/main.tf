# Managed Redis 7 for kseal nonce store, rate limiting, and quotas. Encryption
# in transit + at rest, AUTH token, Multi-AZ automatic failover, private only.

# Only generate an AUTH token when AUTH is actually used (requires transit
# encryption); otherwise no secret is created and none lands in state.
resource "random_password" "auth" {
  count   = var.auth_enabled && var.transit_encryption_enabled ? 1 : 0
  length  = 48
  special = false # ElastiCache AUTH tokens reject most special chars.
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "${var.name}-redis"
  subnet_ids = var.subnet_ids
  tags       = var.tags
}

resource "aws_security_group" "this" {
  name        = "${var.name}-redis"
  description = "kseal Redis access"
  vpc_id      = var.vpc_id
  tags        = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "ingress_sg" {
  count                    = length(var.allowed_security_group_ids)
  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6379
  protocol                 = "tcp"
  security_group_id        = aws_security_group.this.id
  source_security_group_id = var.allowed_security_group_ids[count.index]
  description              = "kseal workloads"
}

resource "aws_security_group_rule" "ingress_cidr" {
  count             = length(var.allowed_cidr_blocks) > 0 ? 1 : 0
  type              = "ingress"
  from_port         = 6379
  to_port           = 6379
  protocol          = "tcp"
  security_group_id = aws_security_group.this.id
  cidr_blocks       = var.allowed_cidr_blocks
  description       = "Extra allowed CIDRs"
}

resource "aws_elasticache_parameter_group" "this" {
  name        = "${var.name}-redis7"
  family      = "redis7"
  description = "kseal Redis 7 parameters"
  tags        = var.tags

  # Evict volatile keys under memory pressure (TTL'd nonces/rate-limit buckets).
  parameter {
    name  = "maxmemory-policy"
    value = "volatile-lru"
  }
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = "${var.name}-redis"
  description          = "kseal ${var.name} Redis"

  engine         = "redis"
  engine_version = var.engine_version
  node_type      = var.node_type
  port           = 6379

  num_node_groups            = var.num_node_groups
  replicas_per_node_group    = var.replicas_per_node_group
  automatic_failover_enabled = var.replicas_per_node_group >= 1
  multi_az_enabled           = var.replicas_per_node_group >= 1

  subnet_group_name    = aws_elasticache_subnet_group.this.name
  security_group_ids   = [aws_security_group.this.id]
  parameter_group_name = aws_elasticache_parameter_group.this.name

  at_rest_encryption_enabled = true
  transit_encryption_enabled = var.transit_encryption_enabled
  kms_key_id                 = var.kms_key_arn != "" ? var.kms_key_arn : null
  # AUTH requires transit encryption; only set when both are on.
  auth_token                 = var.auth_enabled && var.transit_encryption_enabled ? one(random_password.auth[*].result) : null
  auth_token_update_strategy = var.auth_enabled && var.transit_encryption_enabled ? "ROTATE" : null

  snapshot_retention_limit   = var.snapshot_retention_days
  snapshot_window            = "05:00-06:00"
  maintenance_window         = "sun:06:30-sun:07:30"
  apply_immediately          = false
  auto_minor_version_upgrade = true

  tags = var.tags
}
