terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }

  # Remote state holds generated DB credentials (sensitive) — keep it in an
  # encrypted, versioned backend. Configure per-account:
  #   terraform init -backend-config=backend.hcl
  backend "s3" {}
}

# Default provider = the primary region. Used by the primary regional stack, the
# (global) Route53 routing module, and the analytics replication config (which
# attaches to the primary/source bucket).
provider "aws" {
  region = var.primary_region
  default_tags {
    tags = local.tags
  }
}

# One aliased provider per candidate replica region. Both are always declared so
# the configuration is valid; a region is only actually used when its
# *_region variable is non-empty (the module count gates creation).
provider "aws" {
  alias  = "replica_a"
  region = var.replica_a_region != "" ? var.replica_a_region : var.primary_region
  default_tags {
    tags = local.tags
  }
}

provider "aws" {
  alias  = "replica_b"
  region = var.replica_b_region != "" ? var.replica_b_region : var.primary_region
  default_tags {
    tags = local.tags
  }
}
