# Cross-region replication for the analytics cold tier. Fans the primary
# region's analytics bucket out to one or more replica-region buckets so the
# cold tier survives a full-region loss (see docs/multi-region.md + the DR
# runbook). Attaches to the SOURCE bucket, so the caller passes the primary
# region's aws provider.

locals {
  # Deterministic ordering so replication-rule priorities are stable across
  # plans regardless of map iteration order.
  dest_regions = sort(keys(var.destinations))
  dest_kms_arns = compact([
    for d in values(var.destinations) : d.kms_key_arn
  ])
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "${var.name}-analytics-repl"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "replication" {
  statement {
    sid       = "SourceListAndConfig"
    effect    = "Allow"
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [var.source_bucket_arn]
  }

  statement {
    sid       = "SourceReadObjects"
    effect    = "Allow"
    actions   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"]
    resources = ["${var.source_bucket_arn}/*"]
  }

  statement {
    sid       = "ReplicateToDestinations"
    effect    = "Allow"
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
    resources = [for d in var.destinations : "${d.bucket_arn}/*"]
  }

  # Decrypt SSE-KMS source objects before replicating them.
  dynamic "statement" {
    for_each = var.source_kms_key_arn != "" ? [1] : []
    content {
      sid       = "DecryptSource"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = [var.source_kms_key_arn]
    }
  }

  # Encrypt replicas with each destination region's key.
  dynamic "statement" {
    for_each = length(local.dest_kms_arns) > 0 ? [1] : []
    content {
      sid       = "EncryptDestinations"
      effect    = "Allow"
      actions   = ["kms:Encrypt"]
      resources = local.dest_kms_arns
    }
  }
}

resource "aws_iam_role_policy" "this" {
  name   = "replication"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.replication.json
}

resource "aws_s3_bucket_replication_configuration" "this" {
  role   = aws_iam_role.this.arn
  bucket = var.source_bucket_id

  dynamic "rule" {
    for_each = local.dest_regions
    content {
      id       = "analytics-to-${rule.value}"
      status   = "Enabled"
      priority = rule.key + 1
      filter {}

      delete_marker_replication {
        status = "Enabled"
      }

      source_selection_criteria {
        sse_kms_encrypted_objects {
          status = var.source_kms_key_arn != "" ? "Enabled" : "Disabled"
        }
      }

      destination {
        bucket        = var.destinations[rule.value].bucket_arn
        storage_class = "STANDARD_IA"

        dynamic "encryption_configuration" {
          for_each = var.destinations[rule.value].kms_key_arn != "" ? [1] : []
          content {
            replica_kms_key_id = var.destinations[rule.value].kms_key_arn
          }
        }
      }
    }
  }
}
