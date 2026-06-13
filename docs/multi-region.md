# kseal multi-region data plane

Phase 4 topology for running kseal across multiple regions: a writable primary
region plus one or more read-mostly replica regions, fronted by a single global
hostname. This serves two product tiers from the isolation model
([ARCHITECTURE.md](../ARCHITECTURE.md)):

- **Enterprise — region pinning.** A tenant's traffic is pinned to its home
  region for latency and data locality.
- **Regulated — data residency.** Clients in a continent are steered to an
  in-region stack so personal data stays in-region (complements private link +
  CMK + the on-prem verifier; see [deployment-private-link.md](./deployment-private-link.md)
  and [deployment-onprem.md](./deployment-onprem.md)).

Everything is **additive**: the existing single-region chart and Terraform envs
keep working unchanged. Multi-region is opt-in.

- [Topology](#topology)
- [Terraform](#terraform)
- [Data replication](#data-replication)
- [Global routing & region pinning](#global-routing--region-pinning)
- [Helm: region-scoped releases](#helm-region-scoped-releases)
- [Failover](#failover)
- [Validation](#validation)

---

## Topology

```
                       ┌─────────────────────────────────────┐
   clients (SDKs,  ───►│ Route53: api.kseal.example.com       │
   devices)            │ latency routing + health checks       │
                       │  (or geolocation for residency)        │
                       └───┬───────────────┬───────────────┬───┘
                           │               │               │
                ┌──────────▼──────┐ ┌──────▼─────────┐ ┌───▼────────────┐
                │ us-east-1       │ │ eu-west-1      │ │ ap-southeast-1 │
                │ PRIMARY         │ │ REPLICA        │ │ REPLICA        │
                │ Helm release    │ │ Helm release   │ │ Helm release   │
                │ (read/write)    │ │ (read-mostly)  │ │ (read-mostly)  │
                ├─────────────────┤ ├────────────────┤ ├────────────────┤
                │ Postgres 16     │ │ PG read replica│ │ PG read replica│
                │  (writer)  ─────┼─┼──► (cross-region replication) ◄────┤
                │ analytics S3 ───┼─┼──► analytics S3 │ │ analytics S3   │
                │  (CRR source)   │ │  (CRR dest)    │ │  (CRR dest)    │
                └─────────────────┘ └────────────────┘ └────────────────┘
```

Each region is an independent Helm release of the existing chart, scoped with a
`region` block. Cross-region state movement (Postgres replication, analytics S3
replication) and the global hostname are provisioned by Terraform.

---

## Terraform

Root: [`deploy/terraform/envs/multi-region`](../deploy/terraform/envs/multi-region).
Composed from three modules:

| Module | Purpose |
| --- | --- |
| [`modules/multi-region`](../deploy/terraform/modules/multi-region) | One **regional stack**: Postgres node (primary writer or cross-region read replica) + analytics cold-tier S3 bucket (versioned, encrypted, TLS-only). Instantiated once per region with that region's `aws` provider. |
| [`modules/analytics-replication`](../deploy/terraform/modules/analytics-replication) | S3 cross-region replication (fan-out) from the primary analytics bucket to each replica bucket, with a least-privilege IAM role. Attached to the primary/source bucket. |
| [`modules/global-routing`](../deploy/terraform/modules/global-routing) | Route53 latency/geolocation records + per-region health checks + the per-tenant region-pin SSM parameter. |

The root declares one aliased `aws` provider per candidate region (a primary
plus two optional replicas) and gates replica creation on whether
`replica_a_region` / `replica_b_region` are set, so the **same root** runs both
single-region and multi-region.

> **Why replication lives at the env level, not inside the regional module.** A
> replica region's Postgres depends on the primary's instance ARN, while the
> primary's analytics replication depends on the replica regions' buckets. If
> both lived in one module the two would form a dependency cycle. Keeping
> analytics replication as a separate module the env wires last keeps the graph
> a DAG.

Examples:

- [`single-region.tfvars.example`](../deploy/terraform/envs/multi-region/single-region.tfvars.example) — one primary, no replicas (default).
- [`terraform.tfvars.example`](../deploy/terraform/envs/multi-region/terraform.tfvars.example) — primary + two replicas.

```bash
cd deploy/terraform/envs/multi-region
cp backend.hcl.example backend.hcl            # point at your state bucket
cp terraform.tfvars.example terraform.tfvars  # fill in VPC/subnet/SG/KMS IDs
terraform init -backend-config=backend.hcl
terraform plan
```

---

## Data replication

**Postgres.** The primary region runs the writable instance with automated
backups (a prerequisite for cross-region replicas). Each replica region creates
a cross-region read replica (`replicate_source_db` → primary ARN) encrypted with
a **region-local KMS key**, behind a region-local security group and parameter
group (`rds.force_ssl = 1`). Replicas serve the read path
(`replica_postgres_addresses` output); all writes go to the primary.

**Analytics cold tier (S3).** The primary's analytics bucket replicates to each
replica bucket via `aws_s3_bucket_replication_configuration` (one rule per
destination, deterministic priorities). All buckets are versioned (required for
replication), SSE-KMS/SSE-S3 encrypted, public-access-blocked, and TLS-only. The
replication IAM role is scoped to exactly the source/destination buckets and the
source/destination KMS keys.

> The hot analytics store (ClickHouse) is deployed per region by its own
> workload; this root manages the **cold tier (S3)** replication that underpins
> cross-region durability and the DR runbook. Region-local hot data is
> reconstructable from the replicated cold tier + the primary Postgres.

---

## Global routing & region pinning

`modules/global-routing` resolves one global hostname (e.g.
`api.kseal.example.com`) to a regional endpoint:

- **`routing_policy = "latency"` (default):** each client reaches the
  lowest-latency healthy region.
- **`routing_policy = "geolocation"`:** clients are steered by continent
  (`geolocation_routes`) for data residency, with a default record
  (`default_region`) for everything else. Route53 forbids mixing routing
  policies on one record name, so this is an explicit either/or.

**Per-tenant region pinning.** `tenant_region_pins` (`tenant_id => region`) is
published as a single JSON **SSM parameter**
(`/kseal/<name>/tenant-region-pins`). The control-plane router reads it (grant
`ssm:GetParameter` on `tenant_region_pins_ssm_arn`) to pin an Enterprise/
Regulated tenant's traffic to its home region regardless of client geography.
DNS handles the global edge; the SSM map handles tenant-level overrides. No
per-tenant schemas or DNS records are created — pinning stays logical, matching
the `tenant_id` isolation model (~5000 SME tenants).

---

## Helm: region-scoped releases

Each region is its own release. The chart's `region` block:

```yaml
region:
  name: eu-west-1      # stamps topology.kubernetes.io/region + kseal.io/region-role
  role: replica        # primary | replica
  nodeAffinity:
    enabled: true      # pin pods to in-region nodes
    required: true     # hard constraint (false = strong preference)
```

It adds the region labels (`topology.kubernetes.io/region`,
`kseal.io/region-role`) to every object and optionally pins pods to in-region
nodes. Regional endpoints (ingress hosts, console `apiBaseUrl`) and per-region
secret prefixes are set in a region overlay — see
[`values-region-example.yaml`](../deploy/helm/kseal/values-region-example.yaml):

```bash
helm upgrade --install kseal-eu deploy/helm/kseal -n kseal-eu \
  -f deploy/helm/kseal/values-prod.yaml \
  -f deploy/helm/kseal/values-region-example.yaml
```

Single-region releases set nothing new (`region.name` defaults to empty) and
render exactly as before.

---

## Failover

Per-region Route53 health checks (`enable_health_checks = true`, probing
`/readyz` over HTTPS) withdraw an unhealthy region from DNS within a few probe
intervals, so latency/geolocation routing self-heals. Promoting a replica to
writer on a full primary-region loss is a deliberate, documented step — see the
**region failover** procedure and RTO/RPO targets in
[deployment-disaster-recovery.md](./deployment-disaster-recovery.md).

---

## Validation

```bash
terraform -chdir=deploy/terraform/envs/multi-region init -backend=false
terraform -chdir=deploy/terraform/envs/multi-region validate
terraform -chdir=deploy/terraform fmt -check -recursive

helm lint deploy/helm/kseal \
  -f deploy/helm/kseal/values-prod.yaml \
  -f deploy/helm/kseal/values-region-example.yaml
helm template kseal-eu deploy/helm/kseal \
  -f deploy/helm/kseal/values-prod.yaml \
  -f deploy/helm/kseal/values-region-example.yaml | kubeconform -strict -ignore-missing-schemas
```
