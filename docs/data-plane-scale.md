# Scaling the data plane: Kafka/Redpanda + ClickHouse + OTLP (WS-Q)

This document is the operator contract for the **production telemetry data
plane**. The server ships with an in-memory broker + analytics store (the MVP
default); this wave adds **drop-in Kafka/Redpanda and ClickHouse backends behind
the existing interfaces**, plus real OpenTelemetry spans and metrics on the hot
paths.

Everything here is **fail-safe and default-off**: with no new environment set,
the server behaves exactly as before (in-memory broker + store). A backend is
engaged only when its selector env var is flipped, and a misconfigured selection
**fails closed at startup** with a clear error rather than silently degrading.

The `QueryService` wire shapes are unchanged. The same RPCs return identical
results whether they read from the in-memory store or ClickHouse, so SDKs,
consoles, and cross-tenant isolation tests are unaffected.

---

## Architecture

```
SubmitTelemetry ──► Service ──► Broker.Publish ─┐         ┌─► AnalyticsStore.Write ─► QueryService
  (accept-time,    (validate,   (non-blocking,  │ Writer  │   (batched, async)
   per-tenant       privacy      load-shedding) ▼ (drain) ▲
   quota)           allow-list)   Broker.Consume ─────────┘
```

- **Broker** decouples accept-time from write-time. `Publish` never blocks the
  request path: when the buffer is saturated it sheds (`ErrBrokerFull`), the
  same contract for both the in-memory and Kafka brokers.
- **Writer** drains `Consume()` in batches and calls `AnalyticsStore.Write`. On
  shutdown it drains the backlog on a **detached context** so in-flight batches
  are persisted, not cancelled.
- **AnalyticsStore** is the read+write seam `QueryService` sits behind.

### Backends

| Seam | Default (`memory`) | Production (`kafka` / `clickhouse`) |
| --- | --- | --- |
| `Broker` | in-process channel | Kafka/Redpanda, partitioned by tenant, at-least-once |
| `AnalyticsStore` | slice-backed | ClickHouse `ReplacingMergeTree`, tenant-isolated, time-partitioned, TTL'd |

Durability is **at-least-once** end-to-end: Kafka commits offsets only after a
record is handed to the writer, and ClickHouse dedups by event `id`
(`ReplacingMergeTree`), making the pipeline **effectively-once** at query time.

---

## Environment variables

All default-off. Selectors are validated at startup; a selected backend with
missing required connection info **fails closed**.

### Selectors

| Variable | Default | Values | Effect |
| --- | --- | --- | --- |
| `KSEAL_BROKER` | `memory` | `memory` \| `kafka` | Broker implementation |
| `KSEAL_ANALYTICS` | `memory` | `memory` \| `clickhouse` | Analytics store implementation |

### Kafka / Redpanda (`KSEAL_BROKER=kafka`)

| Variable | Default | Notes |
| --- | --- | --- |
| `KSEAL_KAFKA_BROKERS` | `""` | **Required.** Comma-separated seed brokers (`host:port`). |
| `KSEAL_KAFKA_TOPIC` | `kseal.telemetry.events` | Provisioned out-of-band; the broker does **not** auto-create in prod. |
| `KSEAL_KAFKA_CONSUMER_GROUP` | `kseal-analytics-writer` | Writer-side consumer group. |
| `KSEAL_KAFKA_TLS` | `false` | Dial brokers over TLS. |
| `KSEAL_KAFKA_CA_FILE` | `""` | Pin a broker CA (PEM); empty uses system roots. |
| `KSEAL_KAFKA_INSECURE_SKIP_VERIFY` | `false` | Dev/test only. |
| `KSEAL_KAFKA_SASL_MECHANISM` | `""` | `""` \| `plain` \| `scram-sha-256` \| `scram-sha-512`. |
| `KSEAL_KAFKA_SASL_USERNAME` | `""` | SASL user. |
| `KSEAL_KAFKA_SASL_PASSWORD` | `""` | **Secret.** Inject via the Secret/ExternalSecret, never a ConfigMap. |

### ClickHouse (`KSEAL_ANALYTICS=clickhouse`)

| Variable | Default | Notes |
| --- | --- | --- |
| `KSEAL_CLICKHOUSE_ADDR` | `""` | **Required.** Comma-separated `host:port` (native protocol). |
| `KSEAL_CLICKHOUSE_DATABASE` | `kseal` | Database (must already exist). |
| `KSEAL_CLICKHOUSE_USERNAME` | `default` | Connection user. |
| `KSEAL_CLICKHOUSE_PASSWORD` | `""` | **Secret.** Inject via the Secret/ExternalSecret. |
| `KSEAL_CLICKHOUSE_TABLE` | `telemetry_events` | Events table; created by the server (`CREATE TABLE IF NOT EXISTS`). |
| `KSEAL_CLICKHOUSE_CLUSTER` | `""` | Cluster name for `ON CLUSTER` DDL (replicated/sharded). Empty = single-node DDL. |
| `KSEAL_CLICKHOUSE_TLS` | `false` | Dial over TLS. |
| `KSEAL_CLICKHOUSE_CA_FILE` | `""` | Pin a ClickHouse CA (PEM); empty uses system roots. |
| `KSEAL_CLICKHOUSE_INSECURE_SKIP_VERIFY` | `false` | Dev/test only. |
| `KSEAL_CLICKHOUSE_RETENTION_TTL_DAYS` | inherits `KSEAL_RAW_RETENTION_DAYS` | Coarse table-level TTL backstop (see Retention). |

### OTLP (already present, now emitting real telemetry)

| Variable | Default | Notes |
| --- | --- | --- |
| `KSEAL_OTLP_ENDPOINT` | `""` | OTLP gRPC endpoint. Empty = tracing + metrics export disabled. |
| `KSEAL_OTLP_SAMPLE_RATIO` | `0` | Head-sampling ratio, `0.0`–`1.0`. |

---

## ClickHouse schema

The server creates the events table on startup (idempotent
`CREATE TABLE IF NOT EXISTS`). The database itself is **not** auto-created.

```sql
CREATE TABLE IF NOT EXISTS telemetry_events (
  tenant_id    String,
  id           String,
  app_id       String,
  event_type   Int32,
  risk_level   Int32,
  risk_bits    UInt64,
  confidence   Int32,
  build_hash   String,
  policy_hash  String,
  platform     Int32,
  country      String,        -- coarse, allow-listed; never fine-grained PII
  time_bucket  DateTime,
  received_at  DateTime
)
ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (tenant_id, time_bucket, id)
TTL time_bucket + INTERVAL <retention> DAY;
```

- **Tenant isolation:** `tenant_id` is the leading `ORDER BY` column, so every
  per-tenant read is a physical prefix scan and one tenant can never see
  another's rows. All query predicates are bound parameters (injection-safe).
- **Dedup:** `ReplacingMergeTree` keyed by the sort order collapses redelivered
  events (same `id`) — at-least-once delivery becomes effectively-once at query
  time. Counts use `count(DISTINCT id)` so they are correct even before a merge.
  Row-returning reads (`Query`/`ListEvents`) use `FINAL` to collapse duplicates
  on the fly. Because every read pins `tenant_id` (the leading sort key) and a
  time range, `FINAL` only merges parts within one tenant's key range, not the
  whole table — cheap in steady state. If read latency becomes a concern at very
  high volume, migrate these paths to an `argMax` aggregation or a materialized
  view (no `AnalyticsStore` interface change required).
- **Partitioning:** monthly partitions keep retention drops and time-range scans
  cheap.
- **Pagination:** keyset pagination orders recent-first by `(time_bucket, id)`
  for stable cursors at scale.
- **Schema creation vs. evolution:** the store runs `CREATE TABLE IF NOT EXISTS`
  on startup so a fresh cluster or a rolling deploy converges idempotently with
  no separate bootstrap step. It deliberately does **not** auto-`ALTER` an
  existing table. Adding a column to `StoredEvent` is therefore a deliberate,
  ops-controlled migration: run `ALTER TABLE telemetry_events ADD COLUMN ...`
  (with `ON CLUSTER` for a replicated deployment) before rolling out the server
  build that writes it. Online schema mutation of a large `ReplacingMergeTree`
  rewrites parts and touches the `ORDER BY` key, so it is not something to do
  silently on every boot.

---

## Retention & privacy

- **Privacy:** telemetry carries no PII. Only the existing allow-listed, coarse
  fields are persisted (e.g. `country` as a coarse string). The Kafka codec and
  ClickHouse columns are a strict subset of `StoredEvent`; there is no free-form
  payload column.
- **Per-tenant retention:** the existing retention Purger drives
  `PurgeRawEventsOlderThan`, implemented for ClickHouse as a strictly
  tenant-scoped, time-bounded `DELETE` (the `WHERE` always pins `tenant_id`).
- **TTL backstop:** the table TTL (`KSEAL_CLICKHOUSE_RETENTION_TTL_DAYS`,
  default = `KSEAL_RAW_RETENTION_DAYS`) is a coarse safety net only; the Purger
  enforces precise per-tenant windows.

---

## Durability & backpressure

- **Non-blocking accept:** `Publish` sheds (`ErrBrokerFull`) instead of blocking
  the request path; per-tenant quota + isolation are preserved upstream. Under
  the Kafka backend "accepted" means *admitted to the pipeline* (handed to the
  async producer), not *durably committed*: the request path never blocks on the
  broker ack. A produce that fails after retries increments
  `kseal.broker.publish_errors` (alert on it); durability is then owned by the
  at-least-once + dedup path below, not by the accept count.
- **At-least-once *through the store*:** a Kafka offset is committed only after
  the writer has **persisted** that record to ClickHouse (the writer calls the
  broker's `Ack` after a successful flush; the broker marks the offset only
  then). So a crash **or a ClickHouse outage** redelivers rather than loses — the
  durable read position never runs ahead of what is actually stored. A failing
  flush is retried with capped backoff instead of being dropped; while it
  retries the writer stops draining, which backpressures the broker (offsets
  simply stay uncommitted, so Kafka holds the backlog up to its retention).
  `kseal.analytics.write_errors > 0` therefore signals a *retrying* outage to
  alert on, not silent data loss. The ClickHouse `ReplacingMergeTree` dedupes the
  eventual redelivery by event id, making the end-to-end result effectively-once.
- **Idempotent producer + `AllISR` acks:** retries never reorder or duplicate
  within a tenant partition.
- **Graceful drain:** on shutdown the writer flushes the backlog on a detached
  context so in-flight batches are persisted; retries during drain are bounded
  by a grace window so a down store cannot hang termination — any events still
  un-persisted stay uncommitted and redeliver on the next start. The broker
  flushes outstanding produces and commits only the persisted (acked) offsets
  before closing.
- **Poison records:** an undecodable Kafka record is counted and committed (not
  retried forever) — it can never become valid, so it is excluded from the
  persist-before-commit path.

### OTLP signals on the hot paths

Spans: `SubmitTelemetry`, `ListEvents`, `GetTenantOverview`, `VerifyAttestation`
(tenant/app/platform attributes). Metrics: `kseal.ingest.accepted` /
`kseal.ingest.rejected` / batch-size histogram, and broker counters
`kseal.broker.{published,publish_errors,shed,consumed,decode_errors}`.

---

## Rollout

### Local dev (docker compose)

The backends run only under the `dataplane` profile, so the default stack is
unchanged:

```bash
# default: in-memory broker + store
docker compose up --build

# production data plane (Redpanda + ClickHouse)
KSEAL_BROKER=kafka KSEAL_ANALYTICS=clickhouse \
  docker compose --profile dataplane up --build
```

The `kseal-server` connection envs already default to the in-network `redpanda`
and `clickhouse` services, and the ClickHouse container bootstraps the `kseal`
database/user — so flipping the two selectors is all that is required.

### Kubernetes (Helm)

Set the backends under `server.config.dataPlane`, deliver passwords via External
Secrets, and open egress:

```yaml
server:
  config:
    dataPlane:
      broker: kafka
      analytics: clickhouse
      kafka:
        brokers: ["b1.kafka.svc:9092", "b2.kafka.svc:9092"]
        tls: true
        saslMechanism: scram-sha-512
        saslUsername: kseal
      clickhouse:
        addr: ["clickhouse.svc:9440"]
        tls: true
networkPolicy:
  egress:
    kafka: { enabled: true }
    clickhouse: { enabled: true }
externalSecrets:
  remoteKeys:
    kafkaSaslPassword: kseal/prod/kafka-sasl
    clickHousePassword: kseal/prod/ch-pass
```

The default-deny NetworkPolicy only opens the Kafka/ClickHouse egress when those
toggles are enabled.

> **Narrow the egress CIDR in production.** `networkPolicy.egress.kafka.cidr` and
> `clickhouse.cidr` default to `0.0.0.0/0` (matching the existing postgres/redis
> entries) so local/dev works out of the box, but that allows egress to *any*
> host on the broker/store port. For production, scope each CIDR to the managed
> backend's real address range — the MSK or ClickHouse Cloud VPC-endpoint /
> PrivateLink subnet (typically a `/28` or a per-endpoint `/32`) — so a
> compromised server pod cannot exfiltrate over those ports. The Terraform
> modules expose the endpoint addresses to feed these values.

> **Align the egress ports with your backend.** The Helm egress defaults
> (`kafka.port: 9092`, `clickhouse.port: 9000`) match a **plaintext, self-hosted**
> deployment (e.g. the docker-compose Redpanda/ClickHouse). The Terraform modules
> target **managed/TLS** endpoints and use different ports — MSK IAM SASL on
> `9098` and ClickHouse native-TLS on `9440`. If you provision via Terraform (or
> otherwise terminate TLS), set `networkPolicy.egress.kafka.port` /
> `clickhouse.port` to match (`9098` / `9440`), or the default-deny policy will
> block the connection.

### Terraform (default-off)

`deploy/terraform/modules/kafka` provisions an **MSK Serverless** cluster (IAM
auth, NoOps, no SASL password to store); `deploy/terraform/modules/clickhouse`
owns the access boundary for a ClickHouse Cloud (PrivateLink) or self-managed
endpoint. Both are wired into `envs/prod`, gated behind:

```hcl
data_plane_kafka_enabled      = true
data_plane_clickhouse_enabled = true
clickhouse_endpoint_host      = "kseal.clickhouse.internal"
```

Outputs `kafka_bootstrap_brokers` and `clickhouse_addr` feed the corresponding
`KSEAL_*` env vars.

### Recommended cutover

1. Provision Kafka + ClickHouse; create the topic out-of-band with a
   tenant-appropriate partition count and retention.
2. Roll out with selectors still `memory`; confirm OTLP signals and egress.
3. Flip `KSEAL_ANALYTICS=clickhouse` on a canary; verify `QueryService` parity
   against the in-memory baseline (counts, ordering, isolation).
4. Flip `KSEAL_BROKER=kafka` on the canary; watch `kseal.broker.shed` and writer
   drain metrics under load.
5. Promote fleet-wide. **Rollback** is flipping the selectors back to `memory`
   and redeploying — no schema or wire change is involved.

---

## Testing

- **Unit:** codec round-trip/validation, config fail-closed selection, Kafka/
  ClickHouse config + TLS/SASL building, writer drain + detached-context flush,
  and a deterministic backpressure/load smoke (`server/data-plane/ingest`).
- **Integration (testcontainers):** real Redpanda + ClickHouse exercise
  publish→Kafka→writer→ClickHouse, dedup, keyset pagination, tenant isolation,
  and retention purge (`tests/dataplane_backends_test.go`). They **skip cleanly**
  when no container runtime is available, keeping `go test ./...` hermetic.
