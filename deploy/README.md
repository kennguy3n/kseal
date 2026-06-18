# deploy

Deployment configuration: Helm chart, Terraform, local cluster, observability, and on-prem bundle.

Contents:

- **`helm/kseal/`** — the Helm chart for the control-plane and data-plane workloads, with `values.yaml` plus environment overlays for dev, staging, prod, and a per-region example.
- **`terraform/`** — cloud infrastructure (clusters, Postgres/CockroachDB, Kafka/Redpanda, ClickHouse, object storage, KMS/HSM, CDN) with `envs/` for dev, staging, prod, and [multi-region](../docs/multi-region.md) (see also [dedicated-tenant tiers](../ARCHITECTURE.md#tenant-isolation)).
- **`kind/`** — a local [kind](https://kind.sigs.k8s.io/) cluster config, dependency manifests, and a smoke test for running kseal end-to-end on a laptop.
- **`observability/`** — Prometheus scrape and adapter rules, Grafana dashboards, alert rules, and an OpenTelemetry collector config.
- **`onprem/`** — an air-gapped Docker Compose bundle and image-mirroring script for self-hosted deployments.
