# Managed Kafka for the kseal telemetry pipeline, using MSK Serverless: no
# broker/partition capacity to size or patch (NoOps), per-tenant partitioning
# handled by the producer, and IAM-only auth so there are no SASL passwords to
# store. Private-only; reachable solely from the kseal workload security groups.
#
# The server talks to this broker over IAM SASL on port 9098. The telemetry
# topic itself is created out-of-band (the broker does not auto-create in
# production) — see docs/data-plane-scale.md.

resource "aws_security_group" "this" {
  name        = "${var.name}-kafka"
  description = "kseal Kafka (MSK Serverless) access"
  vpc_id      = var.vpc_id
  tags        = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "ingress_sg" {
  count                    = length(var.allowed_security_group_ids)
  type                     = "ingress"
  from_port                = 9098
  to_port                  = 9098
  protocol                 = "tcp"
  security_group_id        = aws_security_group.this.id
  source_security_group_id = var.allowed_security_group_ids[count.index]
  description              = "kseal workloads (IAM SASL)"
}

resource "aws_security_group_rule" "ingress_cidr" {
  count             = length(var.allowed_cidr_blocks) > 0 ? 1 : 0
  type              = "ingress"
  from_port         = 9098
  to_port           = 9098
  protocol          = "tcp"
  security_group_id = aws_security_group.this.id
  cidr_blocks       = var.allowed_cidr_blocks
  description       = "Extra allowed CIDRs (IAM SASL)"
}

# Egress is required for MSK Serverless to reach its control plane / metadata.
resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.this.id
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "MSK Serverless egress"
}

resource "aws_msk_serverless_cluster" "this" {
  cluster_name = "${var.name}-telemetry"

  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.this.id]
  }

  # IAM auth only: access is governed by IAM policies on the workload role, so
  # there is no broker password to rotate or leak.
  client_authentication {
    sasl {
      iam {
        enabled = true
      }
    }
  }

  tags = var.tags
}
