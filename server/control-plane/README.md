# server/control-plane

Go services for the **control plane**: tenant IAM, app registry, protection profiles, runtime policy authoring, key management, build proof, compliance, billing, and the admin console.

The control plane is **low-volume, strongly consistent, and the source of truth** for tenants, policies, and key material. It owns secrets (KMS/HSM) and produces the signed artifacts the [data plane](../data-plane) and [device plane](../../sdk) consume. It never sits in the high-volume request path.

**Stack:** Go, Postgres / CockroachDB, S3-compatible object storage, KMS / HSM.

See [ARCHITECTURE.md](../../ARCHITECTURE.md#server-side-architecture-for-100k-tenants) for the full service list. **Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md) (Phase 1+).
