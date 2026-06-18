# kseal — Continuous App Trust Platform

> **Build-time hardening · on-device runtime protection (RASP) · server-side attestation · privacy-preserving telemetry · policy-based enforcement.**

kseal is a continuous app trust platform for mobile and desktop applications. It
combines per-build polymorphic hardening, an on-device runtime self-protection
(RASP) layer, hardware-backed cryptographic binding, platform attestation, and a
server-side decision plane so that **only legitimate, untampered,
policy-compliant app instances can reach protected APIs**. Threats are detected
on the device, scored privately on the server, and enforced on the backend —
where an attacker who controls the phone cannot patch them out.

Everything in this documentation is grounded in one canonical reference
deployment — **Meridian Pay**, a fictional consumer payments app — and a set of
committed, byte-exact fixtures. The numbers come from the test and benchmark
suites you can run yourself. See [`docs/reference/`](docs/reference/) for the
fixtures, measured benchmarks, and the risk-scoring reference.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Running the Tests](#running-the-tests)
- [API Examples](#api-examples)
- [How a Trust Decision Is Made](#how-a-trust-decision-is-made)
- [Documentation](#documentation)
- [Why Server-Side Trust](#why-server-side-trust)
- [What Sets kseal Apart](#what-sets-kseal-apart)
- [Architecture Overview](#architecture-overview)
- [The Four Planes](#the-four-planes)
- [Tech Stack](#tech-stack)
- [Performance](#performance)
- [Developer Journey](#developer-journey)
- [Project Structure](#project-structure)
- [Standards Alignment](#standards-alignment)
- [License](#license)
- [Contributing](#contributing)

---

## Quick Start

The full stack — Go server, Postgres 16, Redis 7, and the React console — runs
from one command.

```bash
make docker-up          # builds + starts server, postgres, redis, console (detached)
```

Once up, the server listens on `:8080` and the console on `:5173`. Verify
health:

```bash
curl -fsS localhost:8080/healthz        # 200 once the process is up
curl -fsS localhost:8080/readyz         # 200 once Postgres + Redis are reachable
curl -fsS localhost:8080/metrics | head # Prometheus metrics
```

Migrations are applied automatically by the server on startup. Stop the stack
(the Postgres volume is preserved):

```bash
make docker-down        # use `make docker-clean` to also drop the volume
```

### Endpoints

| Service | Plane | Auth | Notes |
|---|---|---|---|
| `RegistryService` | Control | **API key required** (`Authorization: Bearer ksk_…`) | Tenants, apps, builds, policies, webhooks |
| `TrustService` | Device | Tenant from request body + signed proof | `GetNonce` → `VerifyAttestation` → `ValidateRequestProof` |
| `ConfigService` | Device | Tenant from request body | Signed, cacheable policy config |
| `IngestService` | Device | Tenant from request body | zstd-compressed telemetry batches |
| `QueryService` | Control | API key required | Dashboard overview, event listing, trust stats |
| `WebhookService` | Control | API key required | HMAC-signed event fan-out |

> **Bootstrapping the first API key.** Control-plane procedures
> (`RegistryService`, `QueryService`, `WebhookService`) require a valid API key;
> an unauthenticated control-plane call returns `401 Unauthenticated`. The
> initial admin tenant and key are seeded through the registry store
> (`registry.Store.CreateTenant` + `CreateAPIKey`), exactly as the integration
> harness does in [`tests/harness_test.go`](tests/harness_test.go). The
> device-plane flow (`TrustService` / `ConfigService` / `IngestService`) needs
> no API key — it is scoped by the `tenant_id` in the request body and gated by
> signed proofs.

The device-plane trust flow is exercised end-to-end (challenge → platform
attestation → trust token → signed request proof → `ALLOW` / `STEP_UP` / `DENY`)
by [`tests/e2e_trust_flow_test.go`](tests/e2e_trust_flow_test.go), which builds
the request proof with the same `RequestProofPreimage` + HMAC-SHA256
construction the Rust SDK uses.

---

## Running the Tests

```bash
make test               # Go server unit tests + Rust core tests
make test-integration   # end-to-end suite under tests/ (cd tests && go test ./...)
```

The integration suite drives the **real** services (registry, trust, ingest,
query, config, webhook) against a real Postgres 16 + Redis 7. It provisions them
automatically via [testcontainers](https://golang.testcontainers.org/) when a
container runtime is available, or uses explicit endpoints when set:

```bash
export KSEAL_TEST_POSTGRES_DSN="postgres://kseal:kseal@localhost:5432/kseal?sslmode=disable"
export KSEAL_TEST_REDIS_ADDR="localhost:6379"
cd tests && go test ./...
```

When neither a DSN nor a container runtime is available, the suite **skips
cleanly** so `go test ./...` stays hermetic. The only mocked dependencies are
the external attestation platforms (Google Play Integrity / Apple App Attest) —
and only their trust-material source is swapped, so the real JWS parsing and
verdict mapping still run.

| Test | What it proves |
|---|---|
| `e2e_trust_flow_test.go` | Full trust chain + anti-replay (replayed/decreasing sequence, wrong nonce/token/key all `DENY`) |
| `e2e_telemetry_test.go` | zstd ingest → read back via `ListEvents` with filters + keyset pagination; quota enforcement |
| `e2e_config_test.go` | Ed25519-signed config envelope, ETag/`If-None-Match` caching, TTL, version rotation |
| `e2e_webhook_test.go` | HMAC-SHA256 signed delivery + retry/backoff on a failing endpoint |
| `e2e_query_overview_test.go` | Per-tenant overview + trust-session stats; cross-tenant reads denied |
| `privacy_contract_test.go` | Telemetry schema carries only minimized, non-PII fields |

The full test surface — **294** Go test functions and **143** Rust device-core
unit tests, plus the cross-language golden vectors — is catalogued in
[`docs/reference/benchmarks.md`](docs/reference/benchmarks.md).

---

## API Examples

The server speaks [Connect](https://connectrpc.com/), so every RPC is reachable
as a plain JSON `POST`. Below uses `curl`; `grpcurl` / `buf curl` work too.

Create a tenant (control plane — needs an API key):

```bash
curl -fsS localhost:8080/kseal.v1.RegistryService/CreateTenant \
  -H "Authorization: Bearer $KSEAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Meridian Pay","slug":"meridian","tier":"growth"}'
```

An unauthenticated control-plane call is rejected:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  localhost:8080/kseal.v1.RegistryService/ListTenants \
  -H "Content-Type: application/json" -d '{}'      # => 401
```

Start the trust flow (device plane — no API key; scoped by `tenant_id`):

```bash
curl -fsS localhost:8080/kseal.v1.TrustService/GetNonce \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"<tenant-uuid>","app_id":"<app-uuid>"}'
```

The returned nonce is bound into a platform attestation token and submitted to
`TrustService/VerifyAttestation`, which returns a short-lived trust token. A
per-request proof is then validated by `TrustService/ValidateRequestProof`. The
complete, runnable sequence (including proof construction) lives in
[`tests/e2e_trust_flow_test.go`](tests/e2e_trust_flow_test.go), and the exact
request/response shapes are committed under
[`docs/reference/fixtures/trust/`](docs/reference/fixtures/trust/).

---

## How a Trust Decision Is Made

A device never decides whether it is trustworthy. It **reports signals**; the
server **decides**. The pipeline is:

```
device signals (wire bits) ─FromWire─► server bits ─Fuse─► Score ─► Level ─► Decision
```

Take scenario **D3** from the canonical fixtures: a repackaged Meridian Pay build
running on a rooted phone that fails platform attestation.

```
device reports   wireTamper (bit 6)        ─FromWire─►  BitAppTamper   (weight 60)
attestation adds BitAttestationFail         (server)                   (weight 70)
fused score      60 + 70 = 130
trust level      CRITICAL          (score ≥ 130)
enforcement      STEP_UP mode
decision         DENY
```

The lesson is the whole product thesis: the tamper bit alone (60) is only
`MEDIUM_RISK` and would just trigger a step-up. It is the **fusion** with the
server-side attestation failure (70) — a signal the client cannot influence —
that crosses `CRITICAL` and denies the action. A cracked client cannot talk its
way out of that.

The exact arithmetic for all five canonical scenarios (D1–D5), the weights, and
the thresholds are in
[`docs/reference/risk-signals.md`](docs/reference/risk-signals.md), and the D3
decision document and the resulting SIEM event are committed under
[`docs/reference/fixtures/`](docs/reference/fixtures/README.md).

---

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Technical architecture and design principles |
| [docs/reference/](docs/reference/) | Canonical Meridian deployment, fixtures, benchmarks, risk-scoring reference |
| [docs/reference/fixtures/README.md](docs/reference/fixtures/README.md) | Byte-exact JSON fixtures + the five canonical scenarios |
| [docs/reference/risk-signals.md](docs/reference/risk-signals.md) | Risk bits, weights, thresholds, scoring math |
| [docs/reference/benchmarks.md](docs/reference/benchmarks.md) | Measured numbers + performance budgets |
| [docs/threat-model.md](docs/threat-model.md) | STRIDE-style threat model per vertical |
| [docs/masvs-mapping.md](docs/masvs-mapping.md) | OWASP MASVS control mapping |
| [docs/masvs-evidence.md](docs/masvs-evidence.md) | MASVS evidence report + native-hardening matrix |
| [docs/siem-integration.md](docs/siem-integration.md) | SIEM egress (Splunk / Sentinel / Elastic) |
| [docs/desktop-sdk.md](docs/desktop-sdk.md) | macOS + Windows desktop SDK integration |
| [docs/byok.md](docs/byok.md) | Customer-managed keys (BYOK) + server hardening env vars |
| [docs/cost-model.md](docs/cost-model.md) | Cost model at 10M / 100M / 300M MAU |
| [docs/README.md](docs/README.md) | Full documentation index |

---

## Why Server-Side Trust

**Pure client-side protection is always bypassable.** Any check that runs only
on a device the attacker controls — root/jailbreak detection, debugger
detection, integrity checks, "is this a real app?" logic — can eventually be
patched out, hooked, or emulated. A motivated attacker with a rooted device, a
hooking framework (Frida, Xposed, objection), and a disassembler will defeat any
single-layer, client-only defense.

kseal does not try to make the client unbreakable. Instead it:

1. **Combines local checks with backend verification.** The device gathers
   signals; the *server* makes the trust decision. The attacker cannot patch the
   server.
2. **Uses per-build polymorphism.** Every protected build is structurally
   different, so a bypass crafted against one build does not transfer to the
   next. An attack goes from "one-time crack" to "recurring effort."
3. **Binds API access to a server-side trust decision.** Access to protected
   APIs is gated by a short-lived, server-issued trust token that encodes app
   instance identity, build hash, current risk state, a server nonce, and the
   active server policy. A cracked client cannot mint its own trust.
4. **Anchors to a recognized standard.** kseal is built against the
   **[OWASP MASVS](https://mas.owasp.org/MASVS/)** — an open, testable,
   vendor-neutral baseline. MASVS-RESILIENCE frames obfuscation, anti-debug, and
   anti-tamper as *defense-in-depth* that raises attacker cost, not as a primary
   control.

The result: breaking the client is necessary but **not sufficient** to abuse the
backend.

---

## What Sets kseal Apart

kseal occupies the same space as AppSealing/DoveRunner, Appdome, Guardsquare
(DexGuard/iXGuard), Promon SHIELD, and Zimperium, and is designed to be
simultaneously **more comprehensive, more robust, more private, more
lightweight, lower cost, and NoOps**.

| Dimension | What kseal does | Why it wins over client-only shielding |
|---|---|---|
| **More comprehensive** | Build-time hardening **+** RASP **+** API attestation **+** privacy engineering **+** MASVS evidence **+** SIEM integration **+** CI release gates **+** policy simulator **+** desktop SDKs | Competitors lead with one pillar (obfuscation *or* RASP *or* attestation); kseal covers the full lifecycle. |
| **More robust** | Backend enforcement, short-lived trust tokens, hardware-backed keys (StrongBox / Secure Enclave), platform attestation, per-build polymorphism | The trust decision lives server-side and rotates constantly, so a static crack decays quickly. |
| **More secure** | No static secrets in the binary; API access bound to *app instance + build hash + risk state + server nonce + server policy* | There is no shared secret to extract; replay and repackaging are detectable server-side. |
| **More private** | No cross-tenant fingerprinting, no raw PII, tenant-scoped rotating identifiers, aggressive event minimization, automated store-disclosure artifacts | Avoids the privacy/regulatory liability of fingerprint-heavy SDKs. |
| **More lightweight** | Lazy/risk-driven scheduling, compact telemetry (protobuf + zstd), CDN-served config, optional modules, **no launch-time network call** | Risk scoring is ~48 ns and a signed proof ~349 ns (see [benchmarks](docs/reference/benchmarks.md)); protection scales with risk, not a fixed heartbeat. |
| **Lower operating cost** | Local build transforms, sparse telemetry, batch ingest, zstd dictionaries, sampling, edge rejection, hot/cold retention | Sparse, compressed, sampled events make 100M-MAU economics viable (see [cost-model.md](docs/cost-model.md)). |
| **NoOps** | Self-service onboarding, vertical policy packs, policy simulator, canary rollout, automatic false-positive guardrails, MASVS reports, SIEM templates | Customers integrate and operate without a professional-services engagement. |

---

## Architecture Overview

kseal is a four-plane system: a **Build plane** that produces protected
binaries, a **Device plane** that runs inside the protected app, a **Data
plane** that ingests signals and makes trust decisions at scale, and a **Control
plane** that manages tenants, policies, keys, and compliance.

```mermaid
flowchart TB
    subgraph Build["Build Plane (in tenant CI/CD)"]
        CICD[Tenant CI/CD] --> PLUGIN[CLI / Gradle plugin / Xcode plugin]
        PLUGIN --> COMPILER[Protection compiler<br/>obfuscation + polymorphism + SDK inject]
        COMPILER --> SIGNED[Signed protected build]
        SIGNED --> STORE[App Store / Play Store]
    end

    subgraph Device["Device Plane (protected app)"]
        STORE --> APP[Protected app]
        APP --> SDK[Native SDK<br/>Android / iOS]
        SDK --> CORE[Rust shared trust core]
        CORE --> RISK[Local risk engine]
        CORE --> KEYS[Hardware-backed key + platform attestation]
        RISK --> TELEM[Compressed signed telemetry]
        KEYS --> PROOF[API request proof]
    end

    subgraph Data["Data Plane (global edge)"]
        TELEM --> EDGE[Global edge<br/>HTTP/2, HTTP/3 where mature]
        PROOF --> EDGE
        EDGE --> VERIFY[Attestation verifier]
        EDGE --> INGEST[Event ingest]
        VERIFY --> DECIDE[Policy decision]
        INGEST --> DECIDE
        DECIDE --> GW[Tenant API gateway / webhook / SIEM]
    end

    subgraph Control["Control Plane"]
        TENANTS[Tenants / apps / builds / policies]
        KM[Key management]
        RULES[Risk rules]
        DASH[Dashboards]
        AUDIT[Audit]
        BILL[Billing]
        PRIV[Privacy disclosures]
    end

    Control -. configures .-> Build
    Control -. signs config / policy .-> Device
    Control -. owns rules + keys .-> Data
    DECIDE -. feeds .-> DASH
```

**Reading the flow end-to-end:**

- **Tenant CI/CD → protected build.** The tenant's pipeline invokes the kseal CLI
  or the Gradle/Xcode plugin. The protection compiler applies obfuscation,
  per-build polymorphism, and SDK injection, then emits a signed, protected build
  that ships to the App Store / Play Store.
- **Protected app → request proof.** At runtime the native SDK delegates shared
  logic to the Rust trust core, which runs the local risk engine, manages
  hardware-backed keys and platform attestation, emits compressed signed
  telemetry, and produces a per-request API proof.
- **Global edge → decision.** Telemetry and proofs hit the global edge over
  HTTP/2 (HTTP/3 where the stack is mature). The attestation verifier and event
  ingest feed a policy decision surfaced to the tenant's API gateway, webhooks,
  or SIEM.
- **Control plane → everything.** The control plane owns tenants, apps, builds,
  policies, key material, risk rules, dashboards, audit, billing, and privacy
  disclosures, and configures the other three planes.

---

## The Four Planes

| Plane | Responsibility | Primary stack |
|---|---|---|
| **Control plane** | Tenant/app/build registry, policy authoring, key lifecycle, risk rules, dashboards, audit, billing, privacy disclosures | Go, Postgres / CockroachDB, object storage (S3-compatible), KMS / HSM |
| **Data plane** | High-volume edge ingest, attestation verification, trust sessions, event processing, risk scoring, analytics, webhook/SIEM fan-out | Go, Kafka / Redpanda, ClickHouse, Redis / Dragonfly, CDN |
| **Build plane** | Build-time hardening and SDK injection, per-build polymorphism, build proof generation | Gradle plugin, Xcode plugin, Rust/C++ transforms, isolated build workers |
| **Device plane** | On-device RASP probes, crypto binding, local risk engine, telemetry, request proof | Native iOS (Swift/ObjC), Native Android (Kotlin/Java + NDK), Rust core |

> **Design principle:** the **control plane** (low-volume, strongly consistent,
> owns secrets and policy) is strictly separated from the **data plane**
> (high-volume, eventually consistent, never the source of truth for secrets).
> See [ARCHITECTURE.md](ARCHITECTURE.md#core-design-principle) for the full
> responsibility matrix.

---

## Tech Stack

### On-device

| Concern | Choice | Notes |
|---|---|---|
| Android app layer | Kotlin / Java | Public SDK surface, lifecycle integration |
| Android native | NDK (C/C++) | Native probes, anti-tamper, JNI bridge to Rust |
| iOS app layer | Swift / Objective-C | Public SDK surface, App Attest / DeviceCheck integration |
| Shared trust core | **Rust** | Policy evaluation, event normalization, crypto message formats, compression, deterministic serialization, FFI-safe shared logic |
| Wire format | **Protobuf** | Compact, schema-versioned, deterministic |
| Compression | **zstd** (+ dictionaries) | Small telemetry batches over the wire |

### Server

The server runs self-contained on a single machine and scales out by switching
individual subsystems to their production backends via environment variables.
Both columns are real code paths exercised by the test suite — the default
backends are full implementations, not stubs.

| Concern | Default (single binary) | Scale-out target |
|---|---|---|
| Services | Go | Go |
| RPC | Connect over HTTP/2 (h2c) | gRPC / Connect (HTTP/2) |
| Streaming / ingest | In-process channel broker | Kafka / Redpanda (`KSEAL_BROKER=kafka`) |
| Analytics store | In-memory store | ClickHouse (`KSEAL_ANALYTICS=clickhouse`) |
| Transactional store | Postgres 16 (row-level-security isolation) | Postgres / CockroachDB |
| Cache / sessions | Redis 7 | Redis / Dragonfly |
| Key material | AES-256-GCM envelope under a 32-byte KEK | KMS / HSM-sourced KEK |
| Observability | Prometheus `/metrics`, `/healthz`, `/readyz`; OTLP opt-in (`KSEAL_OTLP_ENDPOINT`) | OpenTelemetry collector |
| Edge | Single Go origin over HTTP/2 | CDN with HTTP/3 termination |

See [`docs/data-plane-scale.md`](docs/data-plane-scale.md) and the full tables in
[ARCHITECTURE.md](ARCHITECTURE.md#tech-stack).

---

## Performance

kseal is invisible to end users. The on-device SDK operates within hard budgets,
and the trust-core hot paths are measured by a committed benchmark suite
(`cargo bench --bench core_benches`):

| Path | Median | Path | Median |
|---|---|---|---|
| Trust core construct (`core_new`) | ~158 ns | Signed request proof (`request_proof_generate`) | ~349 ns |
| Risk score (`policy_evaluate`) | ~48 ns | Proof verify (`request_proof_verify`) | ~357 ns |
| Config verify (Ed25519) | ~54 µs | Batch + zstd (10 events) | ~35 µs |

| Budget | Target |
|---|---|
| Startup overhead (p95) | **< 40 ms** |
| Resident memory | **< 3–5 MB** |
| Android binary (AAR) | **< 500 KB** |
| iOS binary slice | **< 800 KB** |
| CPU (average) | **< 0.5%** |
| Config fetch (p95) | **< 100 ms** (CDN) |
| Network at launch | **none** |

Risk scoring costs tens of nanoseconds and a signed proof is sub-microsecond, so
kseal can score every sensitive action locally with no user-visible cost. Full
measurements and the budget rationale are in
[`docs/reference/benchmarks.md`](docs/reference/benchmarks.md).

---

## Developer Journey

kseal is NoOps and self-service, designed so a developer sees value in minutes
and reaches production-grade enforcement without a services engagement. Start
from the guided **"Secure your app"** walkthrough
([`site/secure-your-app.md`](site/secure-your-app.md)) or a runnable sample under
[`examples/`](examples/) (Android, iOS, macOS, backend); the console's first-run
onboarding stepper handles the rest. The `kseal` CLI mirrors this with
`kseal init` (guided setup) and `kseal doctor` (tells you exactly what to do
next).

| Time | Outcome |
|---|---|
| **15 minutes** | Create a tenant, register an app, install the SDK, and see a **test-mode** risk event in the dashboard. |
| **1 hour** | Add API attestation and a **signed request proof** to one sensitive endpoint. |
| **1 day** | Wire in the build-time hardening plugin (Gradle/Xcode) and ship a protected **staging** build. |
| **1 week** | Use the policy simulator to tune rules, add a **CI release gate**, light up dashboards, and stream events to **SIEM**. |
| **Ongoing** | Automatic SDK updates, false-positive guardrails, and per-release diff reports keep protection current with zero ops. |

---

## Project Structure

```
kseal/
├── README.md                    # Project overview (this file)
├── ARCHITECTURE.md              # Technical architecture
├── cmd/
│   └── kseal-cli/               # CLI: build-time protection + tenant management
├── server/
│   ├── control-plane/           # Go: tenant IAM, app registry, policy, billing, admin
│   ├── data-plane/              # Go: attestation verifier, trust session, event ingest, risk engine
│   └── shared/                  # Shared server libs (auth, middleware, config, observability)
├── sdk/
│   ├── android/                 # Android SDK (Kotlin/Java + NDK)
│   ├── ios/                     # iOS SDK (Swift/ObjC)
│   ├── desktop/                 # Desktop SDKs: macOS (SwiftPM) + Windows (.NET) on the C FFI
│   └── rust-core/               # Shared Rust trust core (policy eval, crypto, compression, serialization)
├── plugins/
│   ├── gradle/                  # Gradle build-time hardening plugin (+ native .so CFI/MTE posture)
│   └── xcode/                   # Xcode build-time hardening plugin (+ Mach-O section-hash integrity)
├── tools/
│   ├── masvs-report/            # Per-release MASVS evidence report generator (Markdown + JSON)
│   ├── privacy-manifest/        # iOS PrivacyInfo.xcprivacy generator (App Store privacy manifest)
│   ├── datasafety/              # Google Play Data Safety disclosure helper
│   └── mastg/                   # OWASP MASTG procedure runner
├── web/
│   ├── console/                 # React admin console / dashboard
│   └── partner-console/         # Read-only partner/MSSP console (multi-tenant fleet rollups)
├── proto/                       # Protobuf definitions for all services and SDK communication
├── deploy/                      # Deployment configs (Helm, Terraform multi-region/private-link, on-prem bundle)
├── examples/                    # Runnable sample apps + quickstarts (android, ios, desktop-macos, backend)
├── site/                        # Static docs site (MkDocs)
├── docs/                        # Reference deployment, fixtures, threat model, MASVS, deployment
└── tests/                       # Integration and end-to-end tests
```

---

## Standards Alignment

kseal is built against the **[OWASP MASVS](https://mas.owasp.org/MASVS/)** and
verified with the **OWASP MASTG** test procedures. Coverage spans:

- **MASVS-STORAGE** — secure local storage of sensitive data
- **MASVS-CRYPTO** — correct, current cryptography and key management
- **MASVS-AUTH** — authentication and authorization
- **MASVS-NETWORK** — secure network communication and TLS
- **MASVS-PLATFORM** — safe platform interaction (IPC, WebViews, permissions)
- **MASVS-CODE** — code quality and dependency hygiene
- **MASVS-RESILIENCE** — anti-tamper, anti-debug, obfuscation as defense-in-depth
- **MASVS-PRIVACY** — data minimization, transparency, user control

Every protected release can emit a **MASVS evidence report** mapping shipped
controls to MASVS categories — generated by
[`tools/masvs-report`](tools/masvs-report) from real build-proof data (also
reachable via `kseal build masvs`). See
[docs/masvs-evidence.md](docs/masvs-evidence.md).

---

## License

License to be determined. A `LICENSE` file will be added before the first public
release.

## Contributing

See [ARCHITECTURE.md](ARCHITECTURE.md) for system design and
[`docs/reference/voice-and-style.md`](docs/reference/voice-and-style.md) for the
documentation voice. Run `make test` before opening a pull request.
