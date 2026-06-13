# Backing store for kseal server secrets, consumed in-cluster by the External
# Secrets Operator (ESO) via IRSA. Three secrets map 1:1 to the Helm
# externalSecrets.remoteKeys: <prefix>/kek, <prefix>/postgres-dsn, <prefix>/redis-addr.
#
# ESO reads these (read-only, scoped to this prefix) and renders the Kubernetes
# Secret the kseal Deployment mounts. No secret value is stored in git/state in
# plaintext — Terraform state must itself live in an encrypted backend.

locals {
  secrets = {
    kek          = { name = "${var.secret_prefix}/kek", value = var.kek }
    postgres-dsn = { name = "${var.secret_prefix}/postgres-dsn", value = var.postgres_dsn }
    redis-addr   = { name = "${var.secret_prefix}/redis-addr", value = var.redis_addr }
  }
}

resource "aws_secretsmanager_secret" "this" {
  for_each = local.secrets

  name                    = each.value.name
  kms_key_id              = var.kms_key_arn != "" ? var.kms_key_arn : null
  recovery_window_in_days = var.recovery_window_days
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_version" "this" {
  for_each = local.secrets

  secret_id     = aws_secretsmanager_secret.this[each.key].id
  secret_string = each.value.value
}

# Least-privilege read policy scoped to exactly these secrets.
data "aws_iam_policy_document" "read" {
  statement {
    sid    = "ReadKsealSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [for s in aws_secretsmanager_secret.this : s.arn]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn != "" ? [1] : []
    content {
      sid       = "DecryptKsealSecrets"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = [var.kms_key_arn]
    }
  }
}

resource "aws_iam_policy" "read" {
  name        = "${var.name}-eso-read"
  description = "kseal External Secrets read access (scoped to ${var.secret_prefix}/*)"
  policy      = data.aws_iam_policy_document.read.json
  tags        = var.tags
}

# IRSA trust: only the ESO service account in its namespace may assume the role.
data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:sub"
      values   = ["system:serviceaccount:${var.external_secrets_namespace}:${var.external_secrets_service_account}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eso" {
  name               = "${var.name}-eso"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "eso" {
  role       = aws_iam_role.eso.name
  policy_arn = aws_iam_policy.read.arn
}
