# Evidence & back-testing — the numbers behind the showcase

The team chapters show kseal *doing the job* on the canonical
[Meridian Pay deployment](../reference/fixtures/README.md). This page is the other half of the
proof: the **measured, reproducible numbers** that say the platform is not just present but
*fast, correct, and economical* at SME-at-scale. Every figure here is produced by running the
real code in this repository — the device hot-path benchmarks, the server/core test suites, and
the bottom-up cost model — not by estimation or marketing. The canonical figures live in
[benchmarks](../reference/benchmarks.md); this page reads them through the showcase lens.

Everything below can be regenerated from a clean checkout:

```bash
make test            # Go server unit tests + Rust core tests
make test-integration  # full end-to-end suite (Postgres 16 + Redis 7)
cd sdk/rust-core/kseal-core && cargo bench --bench core_benches   # device hot-path latency
```

---

## 1. Device hot-path latency (Criterion micro-benchmarks)

These are the operations that run **on the user's phone** on the critical path of a
protected request. The on-device budget is "be invisible": no blocking network call at
launch, single-digit-MB memory, sub-40 ms p95 startup overhead. The Criterion benches in
[`sdk/rust-core/kseal-core/benches/core_benches.rs`](../../sdk/rust-core/kseal-core/benches/core_benches.rs)
measure each step directly (AMD EPYC 7763 x86-64 dev host, release profile; phones are slower
but the *shape* holds — these are nanosecond/microsecond operations, orders of magnitude under
any user-perceptible budget).

| Hot-path operation | What it is | Measured (median) |
|---|---|---|
| `core_new` | Initialize the trust core (relevant to the startup budget) | **~158 ns** |
| `policy_evaluate` | Score fused risk bits against the active policy → ALLOW/STEP_UP/DENY | **~48 ns** |
| `request_proof_generate` | HMAC-SHA256 per-request proof (instance key) | **~349 ns** |
| `request_proof_verify` | Verify a request proof | **~357 ns** |
| `config_verify_and_decode_ed25519` | Verify a signed policy-config envelope (Ed25519) + decode | **~54 µs** |
| `batch_and_compress_10` | Build + zstd-compress a 10-event telemetry batch | **~35 µs** |
| `decompress_batch_10` | Decompress a 10-event batch (server side) | **~16 µs** |

**Reading it:** core initialization is ~158 *nanoseconds* — five-plus orders of magnitude under
the **< 40 ms** startup budget — because there is **no launch-time network call**; the heavy
primitives (Ed25519 config verification) only run when a *new signed config* arrives, not per
request. The per-request proof is a single HMAC, sub-microsecond. This is what "lightweight or
it doesn't count" means in numbers, and it backs the budget table in the
[README](../../README.md#performance).

---

## 2. Correctness — the test suites that gate every claim

The showcase only claims a capability if the code that implements it is covered by a passing
test. Two suites run on every change (counts from [benchmarks](../reference/benchmarks.md)):

| Suite | Scope | Count |
|---|---|---|
| Go server (`make test-server`) | 27 packages across control + data plane (registry, attestation, trust, fleet, canary, guardrails, ingest, config, webhook, query, compliance, simulator, SIEM, …) | **294 test functions** |
| Rust trust core (`make test-rust`) | policy eval, risk fusion, anomaly window, crypto proofs, config signing, zstd transport | **143 unit tests** |

The end-to-end suite (`make test-integration`) drives the **real** services against a
real Postgres 16 + Redis 7 and proves the security-critical invariants directly —
these are the tests that make the team stories defensible:

| End-to-end test | Invariant it proves | Maps to chapter |
|---|---|---|
| `e2e_trust_flow_test.go` | Full challenge → attest → token → signed proof chain; **replayed / decreasing-sequence / wrong-nonce / wrong-token / wrong-key all DENY** | [Server-authoritative trust](01-server-authoritative-trust.md) |
| `e2e_telemetry_test.go` | zstd ingest → read back with filters + keyset pagination; quota enforcement | [Incident response & kill switch](03-incident-response-and-kill-switch.md) |
| `e2e_config_test.go` | Ed25519-signed config envelope, ETag / `If-None-Match` caching, TTL, version rotation | [Policy canary rollout](05-policy-canary-rollout.md) |
| `e2e_webhook_test.go` | HMAC-SHA256 signed delivery + retry/backoff on a failing endpoint | [Server-authoritative trust](01-server-authoritative-trust.md) |
| `e2e_query_overview_test.go` | Per-tenant overview + trust-session stats; **cross-tenant reads denied** | all |
| `privacy_contract_test.go` | Telemetry schema carries **only minimized, non-PII fields** | [Compliance evidence](04-compliance-evidence.md) |

The fleet engine's own unit tests (`server/data-plane/fleet/engine_test.go`) include
`TestBaselineLearnThenSurge` and `TestUnobservedScopeIsClean` — i.e. the
[Fleet Anomaly Guard](02-fleet-anomaly-guard.md) "learn the baseline, then catch the surge"
behaviour is a test, not a demo artifact. The canary controller
(`server/data-plane/canary/controller_test.go`) tests that rollback fires above the threshold
**and** is suppressed below the minimum-sample count, and `bucket_test.go` proves cohorting is
deterministic — the [policy-canary](05-policy-canary-rollout.md) guardrail, proven both ways.

> **Two real defects, found because the docs were grounded in the real product.** A
> `uuid = text` filter crash and a seconds-vs-milliseconds timestamp bug were surfaced and
> fixed while driving the platform for these chapters — see [`defects-found.md`](defects-found.md).
> A mockup would have hidden both.

---

## 3. Back-tested abuse detection — the fleet surge

The Fleet Anomaly Guard story is the clearest "back-test": replay a coordinated abuse wave and
confirm the engine catches it without any tuning.

- **Stimulus:** a coordinated burst of `root_jailbreak` attestations against a single
  `pay-android` build cohort, on top of a learned baseline of clean traffic.
- **Result:** the cohort `(tenant, app, build, region)` breaks with a `Surge` verdict, and newly
  arriving attestations for that cohort get the server-derived `FLEET_ANOMALY` bit (position 32,
  weight 50) fused in — a graduated auto step-up to `MEDIUM_RISK`, not a blunt block.
- **Cost of the detection:** **O(1) per event**, in-process, bounded memory via sharded
  LRU-evicted cohort state. The engine introduces **no new per-user identifier** — it works on
  aggregates only, so population detection doesn't create a privacy liability.

This is the exact contract asserted by `TestBaselineLearnThenSurge` (catches the surge) and
`TestUnobservedScopeIsClean` (no false alarms on quiet cohorts), so the capability and the test
agree.

---

## 4. Economics — back-tested unit cost at scale

A capability that the SME can't afford isn't a capability. The
[cost model](../cost-model.md) is a bottom-up, formula-driven estimate of the data-plane
bill at three scales, using representative public-cloud rates. The headline:

| Scale | Daily raw ingest (good design) | Blended infra cost (aggregates default) |
|---|---|---|
| 10M MAU | 1.5 GB/day | **≈ $465/mo** |
| 100M MAU | 15 GB/day | **≈ $585/mo** |
| 300M MAU | 45 GB/day | **≈ $945/mo** |

Two design decisions — visible in the code, not just the spreadsheet — keep cost flat
as MAU grows:

- **No KMS call per token/proof.** Trust tokens are signed **in-process** with rotated
  keys; request proofs verify against **cached public keys**. A naive "KMS sign per
  token" design would cost *thousands* of dollars/month at 100M MAU. kseal's KMS line
  scales with the **tenant** count, not MAU.
- **Sparse, compressed, sampled telemetry.** 2 events/DAU/day at ~250 raw bytes,
  zstd-compressed ~4× on the wire (the `batch_and_compress_10` bench above shows the
  cost is microseconds), versus a chatty heartbeat design's ~20× raw-ingest. Config
  egress is `304`-dominated because config is signed + cacheable + device-cached, so it
  scales with *users*, not events.

This is the number behind the showcase thesis: the whole job — attestation, fleet
analytics, response, compliance — at **cents per thousand MAU**, operable by one
engineer.

---

## 5. What we did *not* claim

Honesty is part of the evidence. Where the dataset doesn't exercise something, we say so rather
than dress it up:

- The [policy-canary](05-policy-canary-rollout.md) chapter describes the rollout mechanics and
  the guardrail. The auto-rollback controller and cohorting are real and tested
  (`controller_test.go`, `bucket_test.go`), but the committed fixtures don't stage a synthetic
  production breach — the behaviour is proven by the tests, not by a manufactured incident.
- The [compliance](04-compliance-evidence.md) MASVS view derives coverage from the registered
  build-manifest module set and the `build_hash` proof. Its own *Gaps & notes* panel states that
  it does **not** ship per-control signed attestation artifacts — it shows exactly what the
  evidence is and isn't.

A compliance and security product that over-claims is worse than useless. The point of
this page is that the claims and the code agree — and you can run both.
