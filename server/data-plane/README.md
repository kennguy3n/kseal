# server/data-plane

Go services for the **data plane**: edge gateway, config service, attestation verifier, trust session service, event ingest, risk engine, analytics writer, and webhook/SIEM fan-out.

The data plane is **very high volume, eventually consistent, and stateless where possible**. It holds no long-lived secrets — only short-lived, scoped credentials — and derives policy/keys-by-reference from signed artifacts produced by the [control plane](../control-plane). It must fail safe and shed load under pressure.

**Stack:** Go, Kafka / Redpanda, ClickHouse, Redis / Dragonfly, CDN.

See [ARCHITECTURE.md](../../ARCHITECTURE.md#server-side-architecture-for-100k-tenants). **Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md) (Phase 1+).
