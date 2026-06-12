# kseal — Development Progress

This document tracks delivery against the six-phase roadmap. Status values: **NOT STARTED**, **IN PROGRESS**, **DONE**.

## Phase Summary

| Phase | Theme | Duration | Status |
|---|---|---|---|
| [Phase 0](#phase-0-research--threat-model-6-8-weeks) | Research & Threat Model | 6–8 weeks | **IN PROGRESS** |
| [Phase 1](#phase-1-api-trust-product-3-4-months) | API Trust Product | 3–4 months | **NOT STARTED** |
| [Phase 2](#phase-2-runtime-protection-4-6-months) | Runtime Protection | 4–6 months | **NOT STARTED** |
| [Phase 3](#phase-3-build-time-hardening-6-9-months) | Build-Time Hardening | 6–9 months | **NOT STARTED** |
| [Phase 4](#phase-4-enterprise-scale-9-12-months) | Enterprise Scale | 9–12 months | **NOT STARTED** |
| [Phase 5](#phase-5-desktop-6-months-after-mobile-maturity) | Desktop | 6+ months post-mobile | **NOT STARTED** |

---

## Phase 0: Research & Threat Model (6-8 weeks)

**Status: IN PROGRESS**

Validate the threat model, standards mapping, platform constraints, and cost model before writing production code.

### Deliverables

| Deliverable | Status | Assignee | Notes |
|---|---|---|---|
| Threat model by vertical (fintech, gaming, health, media) | IN PROGRESS | | STRIDE-style per-vertical attacker profiles |
| MASVS mapping | IN PROGRESS | | Map planned controls to MASVS-STORAGE/CRYPTO/AUTH/NETWORK/PLATFORM/CODE/RESILIENCE/PRIVACY |
| iOS App Review safety review | NOT STARTED | | Confirm no private API use; App Attest/DeviceCheck only |
| Android policy review | NOT STARTED | | Play policy + Play Integrity quota model |
| AppSealing / DoveRunner feature parity matrix | IN PROGRESS | | Feature-by-feature comparison + gaps |
| SDK performance prototype | NOT STARTED | | Measure startup/memory/CPU against budgets |
| Attestation prototype | NOT STARTED | | End-to-end Play Integrity + App Attest verify |
| Cost model at 10M / 100M / 300M MAU | IN PROGRESS | | Ingest, storage, compression, retention math |

### Exit criteria

| Criterion | Status | Notes |
|---|---|---|
| App startup overhead measured (< 40 ms p95) | NOT STARTED | Prototype on representative devices |
| No private iOS API dependency confirmed | NOT STARTED | Static + dynamic review |
| Trust session flow proven end-to-end | NOT STARTED | Challenge → attest → token → signed proof |
| Basic dashboard works | NOT STARTED | Test-mode risk events visible |

---

## Phase 1: API Trust Product (3-4 months)

**Status: NOT STARTED**

**Milestone:** Protect APIs from fake clients and repackaged apps.

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Android SDK | NOT STARTED | | Kotlin/Java + NDK, lifecycle integration |
| iOS SDK | NOT STARTED | | Swift/ObjC, App Attest hooks |
| Rust trust core | NOT STARTED | | Policy eval, normalization, crypto formats, compression |
| Play Integrity verifier | NOT STARTED | | Server-side verification + caching |
| App Attest verifier | NOT STARTED | | Server-side attestation verification |
| Signed request proof | NOT STARTED | | Hardware-bound per-request proof |
| Trust session tokens | NOT STARTED | | Short-lived, bound to instance+build+risk+nonce+policy |
| Config service | NOT STARTED | | Signed, CDN-served config |
| Minimal dashboard | NOT STARTED | | Test-mode events, basic metrics |
| Tenant / app / build registry | NOT STARTED | | Control-plane source of truth |
| Webhooks | NOT STARTED | | Decision/event fan-out |

---

## Phase 2: Runtime Protection (4-6 months)

**Status: NOT STARTED**

> **Default response order = `observe → step-up → block` (block only after simulation).**

### Modules

| Module | Status | Assignee | Notes |
|---|---|---|---|
| Root / jailbreak / emulator / simulator detection | NOT STARTED | | Environment-risk probes |
| Debugger / hook detection | NOT STARTED | | ptrace/sysctl + Frida/Xposed detection |
| App integrity | NOT STARTED | | Repackaging/resigning detection |
| Network MITM risk | NOT STARTED | | Proxy/CA/pinning checks |
| Local risk engine | NOT STARTED | | Signal fusion in Rust core |
| Policy simulator | NOT STARTED | | Replay traffic vs candidate policy |
| False-positive guardrails | NOT STARTED | | Auto-detect anomalous block rates |
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
