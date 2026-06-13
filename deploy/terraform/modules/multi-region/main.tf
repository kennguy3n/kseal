# Regional data-plane stack for a single kseal region. Composed once per region
# by a multi-region environment root (deploy/terraform/envs/multi-region), each
# instance receiving an aws provider pinned to var.region.
#
# - role = "primary": writable Postgres 16 + analytics cold-tier bucket that is
#   the replication SOURCE for every replica region.
# - role = "replica": cross-region read replica of the primary Postgres + an
#   analytics bucket that receives replicated objects.
#
# Single-region operation = one instance with role = "primary" and no replicas;
# the replica resources simply never get created (count = 0).

locals {
  is_primary = var.role == "primary"
  is_replica = var.role == "replica"
  tags = merge(var.tags, {
    "topology.kubernetes.io/region" = var.region
    "kseal.io/region-role"          = var.role
  })
}

# ---------------------------------------------------------------------------
# Postgres (regional node)
# ---------------------------------------------------------------------------

resource "random_password" "master" {
  count            = local.is_primary ? 1 : 0
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}"
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-${var.region}-pg"
  subnet_ids = var.subnet_ids
  tags       = local.tags
}

resource "aws_security_group" "pg" {
  name        = "${var.name}-${var.region}-pg"
  description = "kseal regional Postgres access (${var.region})"
  vpc_id      = var.vpc_id
  tags        = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "pg_ingress_sg" {
  count                    = length(var.allowed_security_group_ids)
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  security_group_id        = aws_security_group.pg.id
  source_security_group_id = var.allowed_security_group_ids[count.index]
  description              = "kseal workloads (${var.region})"
}

resource "aws_db_parameter_group" "this" {
  name        = "${var.name}-${var.region}-pg16"
  family      = "postgres16"
  description = "kseal Postgres 16 parameters (${var.region})"
  tags        = local.tags

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }
}

# Primary: full writable instance with its own credentials + backups.
resource "aws_db_instance" "primary" {
  count = local.is_primary ? 1 : 0

  identifier     = "${var.name}-${var.region}-pg"
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage > 0 ? var.max_allocated_storage : null
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn != "" ? var.kms_key_arn : null

  db_name  = var.db_name
  username = var.master_username
  password = one(random_password.master[*].result)
  port     = 5432

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.pg.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  multi_az               = var.multi_az
  publicly_accessible    = false

  # Cross-region read replicas require automated backups on the source.
  backup_retention_period   = max(var.backup_retention_days, 1)
  backup_window             = "03:00-04:00"
  maintenance_window        = "sun:04:30-sun:05:30"
  copy_tags_to_snapshot     = true
  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-${var.region}-pg-final"

  auto_minor_version_upgrade      = true
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = local.tags
}

# Replica: cross-region read replica of the primary. Inherits engine,
# credentials, and storage size from the source; gets a region-local KMS key,
# subnet group, parameter group, and security group.
resource "aws_db_instance" "replica" {
  count = local.is_replica ? 1 : 0

  identifier          = "${var.name}-${var.region}-pg-replica"
  instance_class      = var.instance_class
  replicate_source_db = var.source_db_arn

  storage_encrypted = true
  kms_key_id        = var.kms_key_arn != "" ? var.kms_key_arn : null

  port                   = 5432
  vpc_security_group_ids = [aws_security_group.pg.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  publicly_accessible    = false

  # A read replica must not take its own final snapshot.
  skip_final_snapshot = true
  deletion_protection = var.deletion_protection

  auto_minor_version_upgrade      = true
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = local.tags
}

# ---------------------------------------------------------------------------
# Analytics cold tier (S3) — versioned, encrypted, private, TLS-only.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "analytics" {
  bucket        = var.analytics_bucket_name
  force_destroy = var.analytics_force_destroy
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "analytics" {
  bucket                  = aws_s3_bucket.analytics.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Versioning is mandatory both for safe cold-tier retention and as a
# precondition for cross-region replication.
resource "aws_s3_bucket_versioning" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != "" ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn != "" ? var.kms_key_arn : null
    }
    bucket_key_enabled = var.kms_key_arn != ""
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "analytics" {
  bucket = aws_s3_bucket.analytics.id

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  dynamic "rule" {
    for_each = var.analytics_noncurrent_version_expiration_days > 0 ? [1] : []
    content {
      id     = "expire-noncurrent-versions"
      status = "Enabled"
      filter {}
      noncurrent_version_expiration {
        noncurrent_days = var.analytics_noncurrent_version_expiration_days
      }
    }
  }
}

data "aws_iam_policy_document" "analytics_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.analytics.arn, "${aws_s3_bucket.analytics.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "analytics_tls_only" {
  bucket = aws_s3_bucket.analytics.id
  policy = data.aws_iam_policy_document.analytics_tls_only.json
}

# Cross-region analytics replication is wired by the standalone
# `analytics-replication` module from the environment root, not here: the
# primary's replication config depends on the replica regions' buckets while a
# replica's Postgres depends on the primary's instance, so keeping replication
# out of the regional module is what avoids a module-level dependency cycle.
