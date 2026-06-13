# kseal deployment

Production-grade, self-healing, autoscaling deployment for the kseal continuous
app-trust platform, plus the CI release gate. Everything here is **NoOps by
design**: GitOps-friendly manifests, External Secrets, autoscaling, and a
release gate that blocks bad builds before they ship.

This document covers:

- [Topology](#topology)
- [Local stack (prod-mirroring)](#local-stack-prod-mirroring)
- [Helm chart](#helm-chart)
- [Scaling](#scaling)
- [Secrets](#secrets)
- [Networking & isolation](#networking--isolation)
- [Migrations](#migrations)
- [Observability](#observability)
- [Terraform (managed dependencies)](#terraform-managed-dependencies)
- [Release gate (CI)](#release-gate-ci)
- [Validation](#validation)
- [Known gaps / follow-ups](#known-gaps--follow-ups)

---

## Topology

```
                         ┌──────────────────────────────────────┐
        clients ───────► │ Ingress (nginx, TLS)                 │
        (SDKs, devices)  └───────────────┬──────────────────────┘
                                         │ h2c (HTTP/2 cleartext)
                          ┌──────────────▼───────────────┐
   operators ──► console │  kseal server (Deployment)     │
   (browser)     (nginx)  │  control-plane + data-plane    │
                          │  Connect RPC on :8080          │
                          │  /healthz /readyz /metrics     │
                          └───┬───────────┬───────────┬────┘
                              │           │           │
                   Postgres 16│   Redis 7 │   OTLP     │ webhooks/SIEM (443)
                  (registry,  │ (nonces,  │ (traces +  │
                   config,    │  rate     │  metrics)  │
                   telemetry) │  limits,  ▼            ▼
                              │  quotas)  OTel collector → Tempo / Prometheus
                              ▼
                       managed (Terraform)
```

- **server** — a single Go binary serving both the control plane (Registry,
  Config, Trust) and the data plane (Ingest, Query) over Connect/gRPC on `:8080`
  (h2c). Stateless; scales horizontally. Reads all config from env
  (`server/shared/config`).
- **console** — static React/Vite SPA served by nginx on `:80`. API base URL is
  injected at container start into `/env.js` (no rebuild per environment).
- **Postgres 16** — system of record (tenants, apps, builds, config, telemetry).
  Row-level security isolates tenants.
- **Redis 7** — attestation nonces, per-tenant rate-limit buckets, ingest
  quotas (all TTL'd).
- **OTel collector / Prometheus / Grafana** — telemetry pipeline.

---

## Local stack (prod-mirroring)

One command brings up a hardened, health-gated local stack that mirrors the
production shape (resource limits, restart policies, dropped capabilities,
read-only rootfs for app containers, private network, runtime config injection):

```bash
make up        # build + start, wait until server /readyz is green
make smoke     # assert server /readyz, /healthz and console respond
make ps        # status + health
make logs      # tail
make down      # stop (keep data)
make clean     # stop + delete volumes
```

Endpoints: server `http://localhost:8080` (`/healthz`, `/readyz`, `/metrics`),
console `http://localhost:5173`.

The compose stack ships a **throwaway dev `KSEAL_KEK`** so envelope-encrypted
rows survive restarts. Override anything via the environment:

```bash
export KSEAL_KEK="$(head -c 32 /dev/urandom | base64)"
export KSEAL_RATE_LIMIT_RPS=500
make up
```

---

## Helm chart

Chart lives at [`deploy/helm/kseal`](../deploy/helm/kseal). Per-environment
overlays: [`values-dev.yaml`](../deploy/helm/kseal/values-dev.yaml),
[`values-staging.yaml`](../deploy/helm/kseal/values-staging.yaml),
[`values-prod.yaml`](../deploy/helm/kseal/values-prod.yaml).

```bash
helm upgrade --install kseal deploy/helm/kseal \
  -n kseal --create-namespace \
  -f deploy/helm/kseal/values-prod.yaml
```

What the chart renders:

| Resource | Purpose |
| --- | --- |
| server `Deployment` | Stateless API; startup/liveness/readiness probes; rolling updates with `maxUnavailable: 0` |
| server `Service` | ClusterIP, `appProtocol: kubernetes.io/h2c` |
| server `HorizontalPodAutoscaler` | CPU + custom RPS metric (see [Scaling](#scaling)) |
| server `PodDisruptionBudget` | `minAvailable` (60% in prod) to survive node drains |
| `migrate` `Job` (Helm hook) | Pre-deploy migration gate (see [Migrations](#migrations)) |
| console `Deployment`/`Service`/`HPA`/`PDB` | Static SPA tier |
| `NetworkPolicy` ×N | Default-deny + scoped ingress/egress |
| `ExternalSecret` | Pulls KEK/DSN/Redis addr from the external store |
| `ServiceMonitor` + `PrometheusRule` | Prometheus Operator integration |
| `Ingress` | API + console hosts, TLS via cert-manager |

Pods run non-root (`uid 10001`), drop all capabilities, disable privilege
escalation, and use `seccompProfile: RuntimeDefault`. The server runs on a
read-only root filesystem with an `emptyDir` at `/tmp`.

> The **console** runs the upstream nginx image (owned by the web workstream)
> which renders `/env.js` and binds `:80` at start, so it uses a slightly
> relaxed profile (writable rootfs + `NET_BIND_SERVICE`/`CHOWN`/`SETUID`/
> `SETGID`). The long-term hardening is to base the console on
> `nginxinc/nginx-unprivileged` — see [Known gaps](#known-gaps--follow-ups).

---

## Scaling

The server HPA (`autoscaling/v2`) scales on **two** signals:

1. **CPU utilization** — `targetCPUUtilizationPercentage` (65% in prod).
2. **Custom RPS metric** — `kseal_rpc_requests_per_second`, a per-pod rate
   derived from `kseal_rpc_requests_total` and published on the
   `custom.metrics.k8s.io` API by **prometheus-adapter**. Install the adapter
   rule from
   [`deploy/observability/prometheus/prometheus-adapter-rules.yaml`](../deploy/observability/prometheus/prometheus-adapter-rules.yaml).
   The HPA targets `server.autoscaling.customMetric.targetAverageValue` RPS per
   pod (120 in prod).

Scale behaviour is tuned for fast scale-up (cope with attestation bursts across
5000 tenants) and conservative scale-down (avoid flapping):

- **up:** up to +100% or +4 pods per 30s, no stabilization.
- **down:** −50% per 60s, 300s stabilization window.

Bounds: prod `minReplicas: 3`, `maxReplicas: 50`. Disruption is bounded by the
PDB and by `topologySpreadConstraints` across zones plus pod anti-affinity
(soft by default, **hard** in prod so no two server pods share a node).

Sizing guidance: start at the per-pod RPS target × `minReplicas`; raise
`maxReplicas` and node-group capacity together. The console scales on CPU only.

---

## Secrets

No secret is ever baked into an image or committed to git. Three secrets drive
the server:

| Key | Meaning |
| --- | --- |
| `KSEAL_KEK` | base64 32-byte key-encryption key (mandatory in prod) |
| `KSEAL_POSTGRES_DSN` | Postgres connection string (`sslmode=require`) |
| `KSEAL_REDIS_ADDR` | Redis `host:port` |

**Flow (prod/staging):**

1. Terraform `external-secrets` module writes the three values into AWS Secrets
   Manager under `kseal/<env>/{kek,postgres-dsn,redis-addr}` and creates an
   IRSA role scoped read-only to exactly those secrets.
2. The [External Secrets Operator](https://external-secrets.io) (annotated with
   that role) reads them and materializes a Kubernetes `Secret`.
3. The chart's `ExternalSecret`
   ([template](../deploy/helm/kseal/templates/externalsecret.yaml)) declares the
   mapping; the server `Deployment` mounts the resulting `Secret` via `envFrom`.

**Rotation:**

- *KEK*: write a new version to Secrets Manager; ESO resyncs within
  `externalSecrets.refreshInterval`; roll the Deployment. The server's envelope
  scheme must support multi-KEK decryption for zero-downtime rotation (server
  workstream).
- *DB/Redis credentials*: rotate at the source (Terraform/RDS), update Secrets
  Manager, ESO resyncs, roll the Deployment.

**Dev**: set `externalSecrets.enabled=false` and create a plain `Secret`
out-of-band (see `values-dev.yaml` for the exact `kubectl create secret`
command). Never commit it.

---

## Networking & isolation

Default-deny `NetworkPolicy` on both tiers, with explicit allowances only:

**Server ingress** — from the ingress controller namespace (API traffic) and the
monitoring namespace (Prometheus scrape of `/metrics`).

**Server egress** — DNS (53), Postgres (5432), Redis (6379), the OTel collector
(4317), and SIEM/webhook sinks (443, scoped to configured CIDRs). Everything
else is denied.

**Console** — ingress from the ingress controller only; egress DNS only.

Per-environment egress CIDRs live in the env overlays
(`networkPolicy.egress.*`). Tenant isolation at the data layer is enforced by
Postgres row-level security (server migrations) and per-tenant rate-limit /
ingest-quota buckets in Redis.

---

## Migrations

The server applies its embedded SQL migrations on startup — idempotent,
checksum-guarded, and transactional (`server/shared/db/migrate.go`). There is no
separate migrate subcommand, so the chart ships a **pre-deploy migration gate**
as a Helm hook ([`migrations-job.yaml`](../deploy/helm/kseal/templates/migrations-job.yaml)):

- Runs as a `pre-install,pre-upgrade` hook (`hook-weight: -5`) before any new
  app replica rolls out.
- Boots the real server binary as a one-shot Job, polls `/readyz` until 200
  (= migrations applied **and** Postgres+Redis healthy), then shuts down and
  exits 0.
- If a migration fails, the server exits non-zero, the Job fails, and the Helm
  release fails atomically — no half-migrated rollout, and no thundering herd of
  freshly-scaled replicas racing to migrate.

`activeDeadlineSeconds` bounds the gate so a stuck migration can't wedge a
release.

---

## Observability

All under [`deploy/observability`](../deploy/observability):

- **OTel collector** ([`otel/otel-collector.yaml`](../deploy/observability/otel/otel-collector.yaml))
  — receives OTLP traces and scrapes the server's Prometheus `/metrics`, fanning
  out to a tracing backend (Tempo/Jaeger) and a metrics TSDB via remote write.
- **Prometheus** — either the chart's `ServiceMonitor`
  (`metrics.serviceMonitor.enabled=true`, kube-prometheus-stack) or the drop-in
  scrape config
  ([`prometheus/prometheus-scrape.yaml`](../deploy/observability/prometheus/prometheus-scrape.yaml))
  for a self-managed Prometheus. The adapter rule publishes the custom HPA
  metric.
- **Grafana dashboard**
  ([`grafana-dashboards/kseal-overview.json`](../deploy/observability/grafana-dashboards/kseal-overview.json))
  — RPC rate/error-ratio, latency **p50/p95/p99** (aggregate + per-procedure),
  ingest/attestation outcomes, webhook/SIEM export by outcome (DLQ = `exhausted`),
  per-tenant rate limiting (quota pressure), and block rate by tenant/app.
- **Alerts** — the chart's `PrometheusRule` and the standalone
  [`alerts/kseal-alerts.yaml`](../deploy/observability/alerts/kseal-alerts.yaml)
  (kept in sync): server down / no-traffic, RPC error rate (warn >5% / crit
  >20%), p99 latency, rate-limit spikes (global + per-tenant), webhook delivery
  failures + DLQ growth, and high block rate.

Metric names come straight from `server/shared/telemetry/metrics.go`:
`kseal_rpc_requests_total`, `kseal_rpc_duration_seconds`,
`kseal_rate_limited_total`, `kseal_ingest_events_total`,
`kseal_webhook_dispatch_total`, `kseal_block_rate`.

---

## Terraform (managed dependencies)

Modules under [`deploy/terraform/modules`](../deploy/terraform/modules), per-env
roots under [`deploy/terraform/envs/{dev,staging,prod}`](../deploy/terraform/envs).
Target cloud is AWS. **Authoring + validation only — never applied here.**

| Module | Provisions |
| --- | --- |
| `postgres` | RDS PostgreSQL 16, gp3 encrypted, Multi-AZ, `rds.force_ssl`, backups + final snapshot, scoped SG, optional Performance Insights / enhanced monitoring |
| `redis` | ElastiCache Redis 7 replication group, at-rest encryption, automatic failover, `volatile-lru`, scoped SG |
| `object-store` | Private S3 bucket: SSE-KMS/SSE-S3, versioning, public-access block, TLS-only bucket policy, lifecycle rules |
| `external-secrets` | Secrets Manager entries (`kseal/<env>/*`) + least-privilege IRSA role for the External Secrets Operator |

Each env wires the modules together (Postgres DSN + Redis addr flow into the
external-secrets module) and is sized per environment (dev: single-AZ, short
retention, `force_destroy`; prod: Multi-AZ, 30-day backups, deletion
protection, hard guarantees).

```bash
cd deploy/terraform/envs/prod
terraform init -backend-config=backend.hcl    # cp backend.hcl.example first
export TF_VAR_kek="$(head -c 32 /dev/urandom | base64)"
terraform plan -var-file=terraform.tfvars      # cp terraform.tfvars.example first
```

State contains generated credentials (marked `sensitive`) — it **must** live in
an encrypted, versioned backend (the S3 backend template enforces `encrypt =
true` + a DynamoDB lock table). `*.tfvars`/`backend.hcl` are gitignored; only
the `.example` templates are committed.

---

## Release gate (CI)

[`.github/workflows/release-gate.yml`](../.github/workflows/release-gate.yml)
runs on PRs, pushes to `main`, and `v*` tags. Every job feeds a required `gate`
job; a release is blocked unless all pass.

| Job | What it enforces |
| --- | --- |
| `proto-drift` | `make proto` then `git diff --exit-code -- server/gen` — committed bindings must match the schema |
| `buf-breaking` | `buf lint` + `buf breaking` against `main` — no backwards-incompatible proto changes |
| `build-test` | `make build` + `make lint` + `make test` (Go server + Rust trust core) |
| `integration` | `make test-integration` against real Postgres 16 + Redis 7 service containers (harness reads `KSEAL_TEST_POSTGRES_DSN` / `KSEAL_TEST_REDIS_ADDR`) |
| `images` | `docker build` server + console images and **Trivy** scan, failing on fixable HIGH/CRITICAL |
| `deploy-validate` | `helm lint` + `kubeconform` (all envs) + `terraform fmt -check` + `terraform validate` (all modules/envs) |
| `gate` | Required check; fails unless every job above succeeded |

Make the `gate` job a required status check on `main` and on the release
workflow to actually block merges/releases.

---

## Validation

Run locally before pushing (mirrors the `deploy-validate` CI job):

```bash
make deploy-lint        # helm lint + kubeconform (dev/staging/prod)
make tf-validate        # terraform fmt -check + validate (modules + envs)
yamllint deploy .github # YAML lint
```

Optional cluster smoke (skips cleanly if kind/kubectl/docker are absent):

```bash
./deploy/kind/smoke.sh  # create kind cluster, deploy chart, assert /readyz, tear down
```

---

## Known gaps / follow-ups

These require changes in workstreams outside `deploy/**` and are intentionally
**not** worked around with hacks:

1. **Console image isn't rootless.** It runs upstream nginx, which needs a
   writable rootfs and `NET_BIND_SERVICE`. Re-base `web/console/Dockerfile` on
   `nginxinc/nginx-unprivileged` (listen `:8080`) to enable a read-only rootfs
   and an empty capability set. *(web workstream)*
2. **Redis TLS + AUTH disabled.** The server connects to Redis with a bare
   `host:port` (no TLS, no password — `server/shared/config`). The Terraform
   `redis` module exposes `transit_encryption_enabled` / `auth_enabled` (default
   off) ready to flip once the server supports `KSEAL_REDIS_TLS` /
   `KSEAL_REDIS_PASSWORD`. *(server workstream)*
3. **Trace export not wired.** The server sets up a global tracer provider but
   attaches no OTLP exporter (`server/shared/telemetry/telemetry.go`), so the
   OTel collector's trace pipeline stays idle until the exporter is added. The
   metrics pipeline works today. *(server workstream)*
