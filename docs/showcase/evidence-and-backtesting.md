# Evidence & back-testing — the numbers behind the showcase

The persona chapters show kseal *doing the job* in a live console. This page is the
other half of the proof: the **measured, reproducible numbers** that say the platform
is not just present but *fast, correct, and economical* at SME-at-scale. Every figure
here is produced by running the real code in this repository — the device hot-path
benchmarks, the server/core test suites, and the bottom-up cost model — not by
estimation or marketing.

Everything below can be regenerated from a clean checkout:

```bash
make test            # Go server unit tests + Rust core tests
make test-integration  # full end-to-end suite (Postgres 16 + Redis 7)
cd sdk/rust-core && cargo bench -p kseal-core   # device hot-path latency
```

---

## 1. Device hot-path latency (Criterion micro-benchmarks)

These are the operations that run **on the user's phone** on the critical path of a
protected request. The on-device budget is "be invisible": no blocking network call at
launch, single-digit-MB memory, sub-40 ms p95 startup overhead. The Criterion benches in
[`sdk/rust-core/kseal-core/benches/core_benches.rs`](../../sdk/rust-core/kseal-core/benches/core_benches.rs)
measure each step directly (x86-64 Linux dev host; phones are slower but the *shape*
holds — these are nanosecond/microsecond operations, orders of magnitude under any
user-perceptible budget).

| Hot-path operation | What it is | Measured (median) |
|---|---|---|
| `core_new` | Initialize the trust core (relevant to the startup budget) | **≈ 129 ns** |
| `policy_evaluate` | Score fused risk bits against the active policy → ALLOW/STEP_UP/DENY | **≈ 49 ns** |
| `request_proof_generate` | HMAC-SHA256 per-request proof (instance key) | **≈ 333 ns** |
| `request_proof_verify` | Verify a request proof | **≈ 444 ns** |
| `config_verify_and_decode_ed25519` | Verify a signed policy-config envelope (Ed25519) + decode | **≈ 49 µs** |
| `batch_and_compress_10` | Build + zstd-compress a 10-event telemetry batch | **≈ 33 µs** |
| `decompress_batch_10` | Decompress a 10-event batch (server side) | **≈ 16 µs** |

**Reading it:** core initialization is ~130 *nanoseconds* — five-plus orders of
magnitude under the **< 40 ms** startup budget — because there is **no launch-time
network call**; the heavy primitives (Ed25519 config verification) only run when a
*new signed config* arrives, not per request. The per-request proof is a single
HMAC, sub-microsecond. This is what "lightweight or it doesn't count" means in
numbers, and it backs the budget table in the [README](../../README.md#performance).

---

## 2. Correctness — the test suites that gate every claim

The showcase only claims a capability if the code that implements it is covered by a
passing test. Two suites run on every change:

| Suite | Scope | Result |
|---|---|---|
| Go server (`make test-server`) | 23 packages across control + data plane (registry, attestation, trust, fleet, canary, guardrails, ingest, config, webhook, query, compliance, simulator, SIEM, …) | **23/23 packages pass, 0 fail** |
| Rust trust core (`make test-rust`) | policy eval, risk fusion, anomaly window, crypto proofs, config signing, zstd transport | **78 tests pass, 0 fail** |

The end-to-end suite (`make test-integration`) drives the **real** services against a
real Postgres 16 + Redis 7 and proves the security-critical invariants directly —
these are the tests that make the persona stories defensible:

| End-to-end test | Invariant it proves | Maps to chapter |
|---|---|---|
| `e2e_trust_flow_test.go` | Full challenge → attest → token → signed proof chain; **replayed / decreasing-sequence / wrong-nonce / wrong-token / wrong-key all DENY** | [NovaPay](01-novapay-fintech.md) |
| `e2e_telemetry_test.go` | zstd ingest → read back with filters + keyset pagination; quota enforcement | [GameForge](03-gameforge-incident-response.md) |
| `e2e_config_test.go` | Ed25519-signed config envelope, ETag / `If-None-Match` caching, TTL, version rotation | [ShopSwift](05-shopswift-release-engineer.md) |
| `e2e_webhook_test.go` | HMAC-SHA256 signed delivery + retry/backoff on a failing endpoint | [NovaPay](01-novapay-fintech.md) |
| `e2e_query_overview_test.go` | Per-tenant overview + trust-session stats; **cross-tenant reads denied** | all |
| `privacy_contract_test.go` | Telemetry schema carries **only minimized, non-PII fields** | [MediToken](04-meditoken-compliance.md) |

The fleet engine's own unit tests (`server/data-plane/fleet/engine_test.go`) include
`TestBaselineLearnThenSurge` and `TestUnobservedScopeIsClean` — i.e. the
[FitPulse](02-fitpulse-noops-sme.md) "learn the baseline, then catch the surge"
behaviour is a test, not a demo artifact. The canary controller
(`server/data-plane/canary/controller_test.go`) tests that rollback fires above the
threshold **and** is suppressed below the minimum-sample count — the
[ShopSwift](05-shopswift-release-engineer.md) guardrail, proven both ways.

> **Two real defects, found because we drove the real product.** A `uuid = text`
> filter crash and a seconds-vs-milliseconds timestamp bug were surfaced and fixed
> while producing the live screenshots — see [`defects-found.md`](defects-found.md).
> A mockup would have hidden both.

---

## 3. Back-tested abuse detection — the FitPulse surge

The Fleet Anomaly Guard story is the clearest "back-test": replay a coordinated abuse
wave and confirm the engine catches it without any tuning.

- **Stimulus:** 320+ `root_jailbreak` attestations against build `fitpulse-3.9` in a
  five-minute window, on top of a learned baseline of clean traffic.
- **Result:** the cohort `(tenant, app, build=fitpulse-3.9, region)` breaks with a
  `Surge` verdict at **422 observations**, and newly arriving attestations for that
  cohort get a server-derived `FLEET_ANOMALY` bit fused in — a graduated auto step-up,
  not a blunt block (screenshot `10`).
- **Cost of the detection:** **O(1) per event**, in-process, bounded memory via
  sharded LRU-evicted cohort state. The engine introduces **no new per-user
  identifier** — it works on aggregates only, so population detection doesn't create a
  privacy liability.

The same logic is unit-tested (`TestBaselineLearnThenSurge`) so the live capture and
the test agree on the contract.

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
  scales with the **tenant** count (~5,000), not MAU — so it's identical (~$10/mo at
  100M) for the good and naive designs.
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

Honesty is part of the evidence. Where the live capture didn't exercise something, we
say so rather than dress it up:

- The [ShopSwift](05-shopswift-release-engineer.md) canary screenshot shows a *healthy*
  freshly-staged 25% rollout (0% candidate block rate, guardrail armed). The
  auto-rollback controller and cohorting are real and tested, but we did **not** force a
  synthetic breach in the capture, so as not to misrepresent a production incident.
- The [MediToken](04-meditoken-compliance.md) MASVS view derives coverage from the
  registered build-manifest module set and the build-hash proof. Its own *Gaps & notes*
  panel states that it does **not** ship per-control signed attestation artifacts — it
  shows exactly what the evidence is and isn't.

A compliance and security product that over-claims is worse than useless. The point of
this page is that the claims and the code agree — and you can run both.
