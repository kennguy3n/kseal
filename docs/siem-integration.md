# SIEM integration

kseal can stream trust/risk telemetry out to a tenant's own SIEM in near real
time. Three sinks are supported today:

| Sink | `SiemKind` | Wire format | Compression |
| --- | --- | --- | --- |
| Splunk HTTP Event Collector | `SPLUNK_HEC` | newline-delimited HEC event envelopes | gzip |
| Microsoft Sentinel (Log Analytics ingestion / DCR) | `SENTINEL` | JSON row array to the DCR stream | gzip |
| Elastic | `ELASTIC` | ECS documents via the `_bulk` API | gzip |

Connectors are **per tenant**. Each connector's auth secret is sealed at rest
with the platform AES-256-GCM-under-KEK envelope (`server/shared/crypto`) and is
**never** returned by the API or shown in the console — only an opaque
`auth_secret_ref` is exposed.

## Privacy contract

The exporter is privacy-preserving by construction. Only the following
**minimized, non-PII** fields can ever leave kseal:

| Field | Meaning |
| --- | --- |
| `tenant_id` | Tenant identifier |
| `app_id` | Application identifier |
| `event_type` | Coarse event class (e.g. `ROOT_RISK`) |
| `risk_level` | Fused trust classification |
| `risk_bits` | Packed bitmask of contributing risk signals (server layout) |
| `risk_signals` | Array of stable per-signal names (e.g. `["debugger","app_tamper"]`); the name-based view of `risk_bits`. Prefer correlating on these names rather than numeric bit positions |
| `confidence` | Coarse confidence bucket |
| `build_hash` | Build identity hash |
| `policy_hash` | Active policy hash |
| `install_key_hash` | Salted, tenant-scoped install-key hash (not reversible to a device) |
| `coarse_time_bucket` | Time bucket (epoch seconds), not a precise timestamp |
| `country_or_region` | Optional coarse geo; omitted when unknown |

Enforcement is layered:

1. The set of canonical fields lives in `server/data-plane/siem/allowlist.go`.
2. A connector may further **narrow** the set via its `field_allow_list`; it can
   never widen it. `NormalizeAllowList` rejects any field outside the contract
   at registration time.
3. At export time every record is projected through `Event.minimized`, which
   intersects the connector allow-list with the canonical set as
   defense-in-depth.
4. `mapping_test.go` and `integration_test.go` walk every emitted JSON payload
   and fail if any key matches a PII substring (email, phone, IMEI, MAC, IP,
   lat/long, device id, advertising id, user id, serial, name, address,
   fingerprint). This is the SIEM analogue of `tests/privacy_contract_test.go`.

No raw timestamps, IPs, device identifiers, or user identifiers are ever
emitted.

## Reliability

The exporter is asynchronous and **backpressured** so a slow or unavailable SIEM
never stalls the ingest path:

- **Per-tenant bounded queue** with non-blocking enqueue; on saturation events
  are load-shed and counted (`kseal_siem_export_total{outcome="dropped"}`)
  rather than blocking producers.
- **Batching** by size or flush interval, then **gzip** where the sink accepts
  it.
- **At-least-once delivery** with a deterministic idempotency key
  (`sha256(connector_id || body)`) sent as `X-Kseal-Idempotency-Key` so retries
  are safe to de-duplicate sink-side.
- **Exponential backoff with full jitter** between attempts.
- **Per-connector circuit breaker** that trips after consecutive failures and
  half-opens after a cooldown.
- **Dead-letter counter** and **export-lag** gauge/histogram exposed on the
  existing Prometheus `/metrics` endpoint.

### Metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kseal_siem_export_total` | counter | `kind`, `outcome` | Export attempts by outcome (`success`, `retry`, `dead_letter`, `dropped`, `circuit_open`, `render_error`) |
| `kseal_siem_dead_letter_total` | counter | `kind` | Batches abandoned after exhausting retries or on permanent failure |
| `kseal_siem_export_lag_seconds` | histogram | — | Delay between event receipt and successful export |
| `kseal_siem_export_lag_latest_seconds` | gauge | — | Most recent export lag |
| `kseal_siem_queue_depth` | gauge | — | In-flight queued events |
| `kseal_siem_batch_events` | histogram | — | Events per delivered batch |

## Per-sink setup

### Splunk HEC

1. In Splunk, create an HTTP Event Collector token with access to the target
   index.
2. Register the connector:
   - **Endpoint**: the HEC base URL, e.g. `https://splunk.example:8088`
     (kseal appends `/services/collector/event`).
   - **Auth secret**: the HEC token (sent as `Authorization: Splunk <token>`).
   - **Index / sourcetype** (optional): defaults to the Splunk token settings;
     the bundled `templates/splunk_props.conf` + `templates/splunk_transforms.conf`
     define the `kseal:trust` sourcetype field extractions.

### Microsoft Sentinel (Log Analytics ingestion / DCR)

1. Create a Data Collection Endpoint (DCE) and a Data Collection Rule (DCR)
   with a custom stream. `templates/sentinel_dcr.json` is a ready-to-edit DCR
   that declares the `Custom-KsealTrust_CL` stream with exactly the contract
   columns.
2. Grant the kseal export identity the *Monitoring Metrics Publisher* role on
   the DCR and obtain a bearer token for the ingestion endpoint.
3. Register the connector:
   - **Endpoint**: the DCE logs ingestion URI.
   - **Auth secret**: the bearer token (sent as `Authorization: Bearer <token>`).
   - **DCR immutable id** and **stream name** are required; kseal posts to
     `/dataCollectionRules/<dcr>/streams/<stream>?api-version=2023-01-01`.

### Elastic (ECS)

1. Create an API key with `create_doc` on the destination index/data stream.
2. Install `templates/elastic_ecs_index_template.json` (matches `kseal-trust-*`)
   so the minimized fields land under ECS `labels` with strict mappings.
3. Register the connector:
   - **Endpoint**: the Elasticsearch base URL (kseal appends `/_bulk`).
   - **Auth secret**: the API key (sent as `Authorization: ApiKey <key>`).
   - **Index**: the target index or data stream, e.g. `kseal-trust-000001`.

## Managing connectors

Use the **SIEM** page in the console (list / add / delete; secrets are
write-only) or the `SiemService` Connect API directly:

- `RegisterConnector` — create a connector for the caller's tenant.
- `ListConnectors` — list connectors (no secrets).
- `DeleteConnector` — remove a connector by id.

All three procedures require a valid control-plane API key and are strictly
tenant-scoped: a request can only ever touch its own tenant's connectors.
