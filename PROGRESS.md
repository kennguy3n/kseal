# kseal — Development Progress

This document tracks delivery against the six-phase roadmap. Status values: **NOT STARTED**, **IN PROGRESS**, **DONE**.

## Phase Summary

| Phase | Theme | Duration | Status |
|---|---|---|---|
| [Phase 0](#phase-0-research--threat-model-6-8-weeks) | Research & Threat Model | 6–8 weeks | **DONE \| 100%** |
| [Phase 1](#phase-1-api-trust-product-3-4-months) | API Trust Product | 3–4 months | **DONE \| 100%** |
| [Phase 2](#phase-2-runtime-protection-4-6-months) | Runtime Protection | 4–6 months | **IN PROGRESS \| ~88%** |
| [Phase 3](#phase-3-build-time-hardening-6-9-months) | Build-Time Hardening | 6–9 months | **NOT STARTED** |
| [Phase 4](#phase-4-enterprise-scale-9-12-months) | Enterprise Scale | 9–12 months | **NOT STARTED** |
| [Phase 5](#phase-5-desktop-6-months-after-mobile-maturity) | Desktop | 6+ months post-mobile | **NOT STARTED** |

---

## Phase 0: Research & Threat Model (6-8 weeks)

**Status: DONE | 100%**

Validate the threat model, standards mapping, platform constraints, and cost model before writing production code.

### Deliverables

| Deliverable | Status | Assignee | Notes |
|---|---|---|---|
| Threat model by vertical (fintech, gaming, health, media) | DONE | | `docs/threat-model.md` — STRIDE-style per-vertical attacker profiles |
| MASVS mapping | DONE | | `docs/masvs-mapping.md` — controls mapped to MASVS-STORAGE/CRYPTO/AUTH/NETWORK/PLATFORM/CODE/RESILIENCE/PRIVACY |
| iOS App Review safety review | DONE | | `docs/ios-app-review.md` — confirms public APIs only; App Attest/DeviceCheck |
| Android policy review | DONE | | `docs/android-policy-review.md` — Play policy + Play Integrity quota model |
| AppSealing / DoveRunner feature parity matrix | DONE | | `docs/feature-parity-matrix.md` — feature-by-feature comparison + gaps |
| SDK performance prototype | DONE | | `sdk/rust-core/kseal-core/benches/core_benches.rs` — Criterion benches for init/proof/compress |
| Attestation prototype | DONE | | `server/data-plane/attestation/{play_integrity,app_attest}.go` — end-to-end verify, proven by `tests/e2e_trust_flow_test.go` |
| Cost model at 10M / 100M / 300M MAU | DONE | | `docs/cost-model.md` — ingest, storage, compression, retention math |

### Exit criteria

| Criterion | Status | Notes |
|---|---|---|
| App startup overhead measured (< 40 ms p95) | DONE | `bench_core_init` in the Rust core benches measures the init budget |
| No private iOS API dependency confirmed | DONE | `docs/ios-app-review.md` static + dynamic review |
| Trust session flow proven end-to-end | DONE | Challenge → attest → token → signed proof, exercised by `tests/e2e_trust_flow_test.go` |
| Basic dashboard works | DONE | React/Vite console under `web/console`; overview backed by `QueryService` (`tests/e2e_query_overview_test.go`) |

---

## Phase 1: API Trust Product (3-4 months)

**Status: DONE | 100%**

**Milestone:** Protect APIs from fake clients and repackaged apps.

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Android SDK | DONE | | Kotlin SDK under `sdk/android` with probes + lifecycle integration |
| iOS SDK | DONE | | Swift SDK under `sdk/ios` with App Attest hooks |
| Rust trust core | DONE | | `sdk/rust-core/kseal-core` — policy eval, normalization, crypto formats, zstd compression |
| Play Integrity verifier | DONE | | `server/data-plane/attestation/play_integrity.go` — server-side verify + caching |
| App Attest verifier | DONE | | `server/data-plane/attestation/app_attest.go` — server-side attestation verify |
| Signed request proof | DONE | | `server/shared/crypto` `RequestProofPreimage` + HMAC; validated by `tests/e2e_trust_flow_test.go` |
| Trust session tokens | DONE | | `server/data-plane/trust` — short-lived tokens bound to instance+build+risk+nonce+policy |
| Config service | DONE | | `server/data-plane/config` — Ed25519-signed config; `tests/e2e_config_test.go` |
| Minimal dashboard | DONE | | React/Vite console under `web/console` backed by `QueryService` |
| Tenant / app / build registry | DONE | | `server/control-plane/registry` — control-plane source of truth |
| Webhooks | DONE | | `server/data-plane/webhook` — HMAC-signed fan-out with retries; `tests/e2e_webhook_test.go` |

---

## Phase 2: Runtime Protection (4-6 months)

**Status: IN PROGRESS | ~88%**

> **Default response order = `observe → step-up → block` (block only after simulation).**

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Root / jailbreak / emulator / simulator detection | DONE | | `RootDetector`/`EmulatorDetector` (Android), `JailbreakDetector`/`SimulatorDetector` (iOS) |
| Debugger / hook detection | DONE | | `DebuggerDetector`/`HookDetector` on both platforms (ptrace/sysctl + Frida/Xposed) |
| App integrity | DONE | | `IntegrityChecker` on both platforms (repackaging/resigning detection) |
| Network MITM risk | DONE | | `NetworkRiskDetector` on both platforms (proxy/CA/pinning checks) |
| Local risk engine | DONE | | `sdk/rust-core/kseal-core/src/risk_engine.rs` — signal fusion in the Rust core |
| Policy simulator | DONE | | `server/data-plane/simulator` — replay traffic vs candidate policy |
| False-positive guardrails | DONE | | `server/data-plane/guardrails` — auto-detect anomalous block rates |
| SIEM integration | NOT STARTED | | Splunk / Sentinel / Elastic templates |

---

## Phase 3: Build-Time Hardening (6-9 months)

**Status: NOT STARTED**

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Gradle plugin | NOT STARTED | | R8-compatible integration |
| Xcode plugin | NOT STARTED | | XCFramework + SwiftPM + build plugin |
| Android obfuscation / resource / string encryption | NOT STARTED | | Layered on R8, mapping-file aware |
| iOS string / symbol hardening | NOT STARTED | | Metadata stripping |
| Native library hardening | NOT STARTED | | .so/Mach-O hardening, CFI/MTE |
| Per-build polymorphism | NOT STARTED | | Randomized structure per build |
| Build proof | NOT STARTED | | Build hash/manifest provenance |
| CI release gate | NOT STARTED | | Block release on policy/compat failure |
| MASVS evidence report | NOT STARTED | | Auto-generated per release |

---

## Phase 4: Enterprise Scale (9-12 months)

**Status: NOT STARTED**

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Multi-region data plane | NOT STARTED | | Region pinning + replication |
| Dedicated tenant tiers | NOT STARTED | | Enterprise/Regulated isolation |
| Customer-managed keys (CMK) | NOT STARTED | | BYOK via KMS/HSM |
| Private link | NOT STARTED | | Private connectivity for regulated tenants |
| On-prem verifier | NOT STARTED | | Customer-hosted attestation verifier |
| Raw event retention controls | NOT STARTED | | Paid raw retention + regional windows |
| Policy packs | NOT STARTED | | Vertical defaults (fintech/gaming/health/media) |
| Compliance dashboards | NOT STARTED | | MASVS + audit + data-processing registry |
| Partner / MSSP console | NOT STARTED | | Multi-tenant management for partners |

---

## Phase 5: Desktop (6+ months after mobile maturity)

**Status: NOT STARTED**

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| macOS SDK | NOT STARTED | | Signature/notarization/hardened-runtime checks |
| Windows SDK | NOT STARTED | | Authenticode/PE integrity checks |
| Desktop API attestation | NOT STARTED | | Trust sessions for desktop |
| Code integrity | NOT STARTED | | Bundle/PE integrity verification |
| Secure updater integration | NOT STARTED | | Signed update channel |
| Enterprise compatibility controls | NOT STARTED | | Policy controls; defer aggressive anti-debug |

---

## Change Log

| Date | Change |
|---|---|
| 2026-06-12 | Initial documentation set created: README, PROPOSAL, ARCHITECTURE, PROGRESS, and project scaffold. Phase 0 marked IN PROGRESS. |
| 2026-06-13 | Full platform delivery merged to `main` and verified end-to-end. **Phase 0 → DONE** (threat model, MASVS mapping, iOS/Android policy reviews, parity matrix, cost model, Rust startup benches, attestation prototype). **Phase 1 → DONE** (all 11 server + SDK modules: registry, trust sessions, Play Integrity + App Attest verifiers, signed request proof, signed config, ingest, query, webhooks, Android/iOS SDKs, Rust trust core, React console). **Phase 2 → IN PROGRESS ~88%** (7 runtime-protection modules done across the Rust core + mobile probes + policy simulator + false-positive guardrails; SIEM integration not started). Added the real end-to-end integration suite under `tests/` (trust flow + anti-replay, telemetry ingest/query with quota, signed config, webhook delivery + retry, query overview + cross-tenant isolation, privacy contract) running against Postgres 16 + Redis 7 via testcontainers. |
