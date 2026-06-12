# deploy

Deployment configuration: Kubernetes manifests, Terraform, and CI templates.

Contents (planned):

- **Kubernetes manifests** — control-plane and data-plane workloads, autoscaling, network policies.
- **Terraform** — cloud infrastructure (clusters, Postgres/CockroachDB, Kafka/Redpanda, ClickHouse, object storage, KMS/HSM, CDN), including [multi-region and dedicated-tenant tiers](../ARCHITECTURE.md#tenant-isolation).
- **CI templates** — drop-in GitHub Actions / GitLab CI / Bitrise snippets for the [build-time hardening](../ARCHITECTURE.md#build-time-hardening) plugins and CI release gates.

**Status:** scaffold — see [PROGRESS.md](../PROGRESS.md) (Phase 1 / Phase 4).
