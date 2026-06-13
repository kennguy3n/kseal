# BYOK / CMK & server security hardening (WS-F)

This document is the **cross-stream contract** for four server capabilities added
in WS-F. Each is gated behind a **fail-safe environment variable that defaults
OFF**, so existing deployments are unaffected until an operator opts in. WS-I
wires these exact variable names into Helm/compose; the server reads them via
`server/shared/config`.

| Variable | Default | Effect when unset (default) |
| --- | --- | --- |
| `KSEAL_CMK_KMS_URI` | `""` | CMK disabled — all tenants use the platform KEK |
| `KSEAL_CMK_KMS_AUTH_TOKEN` | `""` | No bearer token sent to the KMS |
| `KSEAL_REDIS_TLS` | `false` | Plaintext Redis connection |
| `KSEAL_REDIS_CA_FILE` | `""` | System root CAs used for Redis TLS |
| `KSEAL_REDIS_PASSWORD` | `""` | No Redis AUTH |
| `KSEAL_OTLP_ENDPOINT` | `""` | No span exporter attached |
| `KSEAL_OTLP_SAMPLE_RATIO` | `1.0` | Sample every trace |
| `KSEAL_OTLP_INSECURE` | `true` | Plaintext gRPC to the collector |
| `KSEAL_RAW_RETENTION_DAYS` | `30` | Platform-default raw-telemetry window |

---

## 1. Customer-Managed Keys (BYOK / CMK)

Signing-key private material and webhook secrets are sealed with AES-256-GCM
envelope encryption before they touch Postgres. By default this uses a single
platform key-encryption key (`KSEAL_KEK`). CMK lets a tenant supply its own
cloud-KMS key so the platform never holds the key that ultimately protects that
tenant's secrets.

### How it works

- `crypto.TenantSealer` is the seam: `SealForTenant` / `OpenForTenant`. The
  default implementation is the existing `*crypto.Encryptor` (platform KEK,
  unchanged on-disk format).
- When `KSEAL_CMK_KMS_URI` is set, the server builds a `crypto.CMKKeyManager`
  instead. For a CMK-enabled tenant it:
  1. generates a random 32-byte data-encryption key (DEK),
  2. seals the secret under the DEK (AES-256-GCM),
  3. asks the KMS to **wrap** the DEK under the tenant's customer key, and
  4. stores a self-describing envelope (`KSC1` magic + wrapped DEK + ciphertext).
  Opening reverses this, asking the KMS to **unwrap** the DEK.
- The `crypto.KMSClient` interface is the only external touch-point. The
  production implementation (`crypto.HTTPKMSClient`) speaks a small envelope JSON
  API (`POST /v1/wrap`, `POST /v1/unwrap`) compatible with the shape AWS KMS,
  GCP KMS, and Azure Key Vault expose. Tests inject an in-memory fake — no cloud
  is contacted in CI.

### Per-tenant selection

`KSEAL_CMK_KMS_URI` is the **master switch and KMS service endpoint**. Which
tenants actually use CMK is decided per tenant by the `tenants.cmk_kms_uri`
column (migration `010_cmk_kms.sql`):

- column `NULL`/empty → tenant falls back to the platform KEK,
- column set → tenant's DEK is wrapped under that customer key URI.

Operators manage the column with `registry.CMKResolver.SetTenantCMKKeyURI`. The
resolver caches lookups for `registry.DefaultCMKCacheTTL` (30s) to keep the
config-fetch/signing path off the database.

### Fail-closed semantics

- If a tenant is CMK-enabled and the KMS **wrap** fails, the seal is denied (we
  never persist material we cannot later unwrap).
- If a tenant is CMK-enabled and the KMS **unwrap** fails, the open is denied —
  we **never** silently fall back to the platform KEK.
- If a CMK-enabled tenant has legacy platform-sealed material, opening returns
  `crypto.ErrNotCMKEnvelope`. **Rotate the tenant's signing key after enabling
  CMK** so material is re-sealed under the customer key.

> Note: SIEM connector secrets continue to use the platform KEK; CMK currently
> covers control-plane signing keys and webhook secrets.

---

## 2. Redis TLS + AUTH

`server/shared/middleware.NewRedis` takes a `RedisConfig`. Defaults are fully
backward-compatible (plaintext, no AUTH).

- `KSEAL_REDIS_TLS=true` enables TLS (`MinVersion` TLS 1.2).
- `KSEAL_REDIS_CA_FILE` optionally pins a PEM CA bundle for the Redis server
  certificate; empty uses the host's system roots.
- `KSEAL_REDIS_PASSWORD` sets the Redis AUTH credential.

Option construction is pure and unit-tested without a live Redis.

---

## 3. OTLP trace exporter

`server/shared/telemetry.Setup` accepts `telemetry.Options`. With no endpoint it
keeps the previous behavior (spans sampled but not exported).

- `KSEAL_OTLP_ENDPOINT=host:port` attaches a batched OTLP/gRPC span exporter.
  The exporter connects lazily, so the server starts even if the collector is
  briefly unavailable; the batch processor retries.
- `KSEAL_OTLP_SAMPLE_RATIO` (default `1.0`) sets parent-based head sampling.
  Values `<= 0` or `>= 1` sample everything; values in `(0,1)` sample
  probabilistically.
- `KSEAL_OTLP_INSECURE` (default `true`) controls transport security to the
  collector (in-cluster collectors are typically plaintext behind a mesh).

Spans are flushed on shutdown via `Telemetry.Shutdown`, which the server calls
during graceful stop.

---

## 4. Raw-event retention controls

Per-tenant raw-telemetry retention in the data plane. A background purge
(`ingest.Purger`) deletes raw events older than the tenant's window while
derived/aggregate analytics are retained; deletes are strictly per tenant id, so
purging never crosses tenants.

- `KSEAL_RAW_RETENTION_DAYS` (default `30`) is the platform-wide window applied to
  tenants without an explicit override. `<= 0` retains raw events indefinitely
  (fail-safe).
- Per-tenant override lives in the `tenants.raw_retention_days` column (migration
  `011_raw_retention.sql`), managed via
  `registry.RetentionResolver.SetTenantRawRetentionDays`. `NULL` means "use the
  platform default".

The purger is interface-driven (`RawEventStore`, `RetentionResolver`, `Clock`)
and unit-tested with a fake clock; the server runs it hourly.

---

## Proto changes

None. WS-F added no proto fields or RPCs. CMK and retention configuration is
stored on the `tenants` table and managed through operator-facing store methods.
