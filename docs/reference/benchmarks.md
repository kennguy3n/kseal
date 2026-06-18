# Benchmarks & measured numbers

Every performance figure quoted across the kseal documentation traces back to
this page, and every number here is reproducible from the repository. There are
two distinct kinds of number, and the docs never blur them:

- **Measured** — produced by a test or benchmark you can re-run. The exact
  command is given.
- **Budget** — a service-level objective the design holds itself to. Budgets are
  targets the implementation is built around, not claims about a specific
  device.

The canonical reference deployment used throughout the docs — **Meridian Pay** —
is described in [`reference/fixtures/`](fixtures/README.md). The committed
fixtures and these numbers are the only sources the prose is allowed to cite.

---

## Trust-core hot paths (measured)

The device trust core is written in Rust and shared byte-for-byte across every
platform SDK, so its hot paths are the portable, measurable heart of the
client. The figures below come from the committed Criterion benchmark suite:

```bash
cd sdk/rust-core/kseal-core
cargo bench --bench core_benches
```

| Benchmark | What it measures | Median |
|---|---|---|
| `core_new` | Construct a trust core (load policy, init state) | **~158 ns** |
| `policy_evaluate` | Fuse risk bits, score, map to a trust level | **~48 ns** |
| `request_proof_generate` | Produce a signed per-request proof (HMAC) | **~349 ns** |
| `request_proof_verify` | Verify a per-request proof | **~357 ns** |
| `config_verify_and_decode_ed25519` | Verify a signed config envelope (Ed25519) | **~54 µs** |
| `batch_and_compress_10` | Encode + zstd-compress a 10-event batch | **~35 µs** |
| `decompress_batch_10` | Decompress + decode a 10-event batch | **~16 µs** |

> Host for the run above: AMD EPYC 7763 (x86-64), `rustc 1.95.0`, release
> profile. These characterize the *algorithmic* cost of the core, which is the
> part that is identical on every target. Absolute latency on an ARM phone
> differs, but the shape holds: risk scoring is tens of nanoseconds, a signed
> proof is sub-microsecond, and the only double-digit-microsecond paths are the
> ones that run rarely (config verification on refresh, batch compression before
> a network flush).

The practical reading: **trust evaluation is free relative to a network
round-trip.** Meridian Pay can score every sensitive action locally without a
measurable user-visible cost, and only the rare paths (verifying a freshly
fetched policy, compressing a telemetry batch) reach into microseconds.

---

## Test surface (measured)

The contracts the docs describe are pinned by tests, not by prose. Re-run them:

```bash
# Go server + shared libraries
cd server && go test ./...

# Rust device trust core
cd sdk/rust-core/kseal-core && cargo test
```

| Surface | Count | Command |
|---|---|---|
| Go server test functions | **294** | `grep -rE "^func Test" server --include=*.go` |
| Rust device-core unit tests | **143** | `grep -rc "#\[test\]" sdk/rust-core --include=*.rs` |

The cross-language crypto contract is pinned hardest of all. The golden
request-proof tag

```
718bb06df45dc4bbc5bf483bd65acf7609429966adba8baff66fa965857ebd0d
```

is asserted in **four** source files — two on the Go server, two in the Rust
core — so the device and server can never drift on how a proof is computed:

- `server/shared/proof/proof_test.go`
- `server/shared/crypto/crypto_test.go`
- `sdk/rust-core/kseal-core/src/crypto.rs`
- `sdk/rust-core/kseal-core/src/whitebox/mod.rs`

The full set of cross-language vectors (request-proof HMAC, kill-switch Ed25519,
signed-config Ed25519) and how to reproduce them is in
[`reference/fixtures/golden-vectors.json`](fixtures/golden-vectors.json).

---

## Client footprint (budgets)

These are the service-level objectives the SDK is engineered to hold. They are
budgets, not measurements of a specific app build — the actual footprint of any
given integration depends on which modules a tenant enables.

| Budget | Target |
|---|---|
| Startup overhead (p95) | **< 40 ms** |
| Resident memory | **< 3–5 MB** |
| Android binary (AAR) | **< 500 KB** |
| iOS binary slice | **< 800 KB** |
| CPU (average) | **< 0.5%** |
| Crash / ANR contribution | **near-zero** |
| Config fetch (p95) | **< 100 ms** (CDN) |
| Network at launch | **none** |

How the design stays inside these budgets:

- **Lazy checks** — probes run on demand and on sensitive actions, not eagerly
  at launch.
- **Risk-driven scheduling** — check frequency rises only when risk rises.
- **Compact wire format** — protobuf + zstd, packed risk bits (see
  `batch_and_compress_10` above).
- **CDN-served signed config** — never an origin hit per launch; verification is
  the `config_verify_and_decode_ed25519` path.
- **Optional modules** — a tenant ships only the probes it needs.
- **No launch-time network** — all telemetry is deferred and batched; startup
  never blocks on the network.

---

## Server defaults (measured / configured)

The server runs in a self-contained default configuration and scales out by
flipping individual subsystems to their production backends. Both columns are
real: the default is what `go test ./...` exercises and what a single-binary
deployment runs; the scale-out target is the production topology.

| Concern | Default (single binary) | Scale-out target |
|---|---|---|
| RPC | Connect over HTTP/2 (h2c) | gRPC / Connect (HTTP/2) |
| Streaming / ingest | In-process channel broker | Kafka / Redpanda (`KSEAL_BROKER=kafka`) |
| Analytics store | In-memory store | ClickHouse (`KSEAL_ANALYTICS=clickhouse`) |
| Transactional store | Postgres 16 (row-level-security isolation) | Postgres / CockroachDB |
| Cache / sessions | Redis 7 | Redis / Dragonfly |
| Key material | AES-256-GCM envelope under a 32-byte KEK | KMS / HSM-sourced KEK |
| Tracing / metrics | Prometheus `/metrics`, `/healthz`, `/readyz`; OTLP opt-in (`KSEAL_OTLP_ENDPOINT`) | OpenTelemetry collector |
| Edge | Single Go origin over HTTP/2 | CDN with HTTP/3 termination |

The default backends exist so the whole platform runs and is testable on one
machine; the scale-out column is the same code with a different backend
selected by environment variable. No code path is a stub: the in-memory and
in-process backends are full implementations that the test suite runs against.
