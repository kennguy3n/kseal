# server/shared

Shared server libraries used by both the [control plane](../control-plane) and [data plane](../data-plane).

Contents:

- **auth** — service-to-service auth, tenant context, scoped credentials.
- **middleware** — request logging, rate limiting, quota enforcement, tenant isolation guards.
- **config** — signed config loading and validation.
- **crypto** — KEK/KMS key handling, JWT, and dedicated-tenant key material.
- **db** — database access and schema migrations.
- **proof** — per-request proof verification.
- **risk** — the risk-bit contract, weights, and wire→server signal translation.
- **safehttp** — SSRF-guarded outbound HTTP for tenant-controlled egress.
- **telemetry** — OpenTelemetry tracing/metrics/logging helpers.

Keeping these cross-cutting concerns in one place ensures tenant isolation and observability behave identically across every Go service.
