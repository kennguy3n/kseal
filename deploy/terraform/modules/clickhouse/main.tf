# Access boundary for the kseal ClickHouse analytics store. ClickHouse has no
# first-party AWS managed offering, so the cluster itself is ClickHouse Cloud
# (reached over PrivateLink) or self-managed in-VPC; this module owns the
# security group governing who may reach it and surfaces the connection address
# the server uses (KSEAL_CLICKHOUSE_ADDR). TLS + auth are configured on the
# server side (KSEAL_CLICKHOUSE_TLS / KSEAL_CLICKHOUSE_PASSWORD).

resource "aws_security_group" "this" {
  name        = "${var.name}-clickhouse"
  description = "kseal ClickHouse analytics store access"
  vpc_id      = var.vpc_id
  tags        = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "ingress_sg" {
  count                    = length(var.allowed_security_group_ids)
  type                     = "ingress"
  from_port                = var.native_port
  to_port                  = var.native_port
  protocol                 = "tcp"
  security_group_id        = aws_security_group.this.id
  source_security_group_id = var.allowed_security_group_ids[count.index]
  description              = "kseal workloads"
}

resource "aws_security_group_rule" "ingress_cidr" {
  count             = length(var.allowed_cidr_blocks) > 0 ? 1 : 0
  type              = "ingress"
  from_port         = var.native_port
  to_port           = var.native_port
  protocol          = "tcp"
  security_group_id = aws_security_group.this.id
  cidr_blocks       = var.allowed_cidr_blocks
  description       = "Extra allowed CIDRs"
}
