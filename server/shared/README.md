# server/shared

Shared server libraries used by both the [control plane](../control-plane) and [data plane](../data-plane).

Contents (planned):

- **auth** — service-to-service auth, tenant context, scoped credentials.
- **middleware** — request logging, rate limiting, quota enforcement, tenant isolation guards.
- **config** — signed config loading and validation.
- **observability** — OpenTelemetry tracing/metrics/logging helpers.

Keeping these cross-cutting concerns in one place ensures tenant isolation and observability behave identically across every Go service.

**Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md).
