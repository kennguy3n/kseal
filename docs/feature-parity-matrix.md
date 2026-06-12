# kseal — Feature Parity Matrix

A feature-by-feature comparison of **kseal** against the incumbents identified in
the [Market Analysis](../PROPOSAL.md#market-analysis): **AppSealing**
(DoveRunner), **Appdome**, **Guardsquare** (DexGuard / iXGuard), **Promon**
(SHIELD), and **Zimperium** (zDefend / zShield).

The intent is honest positioning, not marketing inflation: for kseal, a cell is
only **has** if the corresponding control is actually implemented; capabilities
on the [roadmap](../PROGRESS.md) are marked **planned** with their phase. The
[Differentiation Thesis](../PROPOSAL.md#differentiation-thesis-vs-appsealing)
explains *how* each kseal claim is made true.

## Legend

| Mark | Meaning |
|---|---|
| **has** | Implemented / generally available as a productized capability |
| **partial** | Partially covered, limited, or available only in some tiers/configs |
| **missing** | Not a productized capability of that vendor |
| **planned (Pn)** | On the kseal roadmap, delivered in phase *n* (see [PROGRESS.md](../PROGRESS.md)) |

> Competitor marks reflect publicly described product positioning at the time of
> this Phase 0 review and the analysis in [PROPOSAL.md](../PROPOSAL.md); they are
> a planning aid, not a contractual claim. Vendor offerings change; revalidate
> before competitive use.

## Table of Contents

- [RASP Modules (1–9)](#rasp-modules-19)
- [Build-Time Hardening](#build-time-hardening)
- [API Attestation & Backend Trust](#api-attestation--backend-trust)
- [Privacy](#privacy)
- [Compliance & Evidence](#compliance--evidence)
- [Enterprise Features](#enterprise-features)
- [Desktop](#desktop)
- [Where kseal Wins, Matches, and Trails](#where-kseal-wins-matches-and-trails)

---

## RASP Modules (1–9)

The nine kseal [runtime modules](../ARCHITECTURE.md#runtime-protection-modules).
Most incumbents cover the classic RASP detections well; kseal's differentiation
is less about *having* a detection and more about **feeding it into a server-side
decision** (covered in [API Attestation](#api-attestation--backend-trust)).

| # | Module | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|---|
| 1 | App integrity (repack/resign) | planned (P2) | has | has | has | has | has |
| 2 | Runtime tamper (in-memory patch) | planned (P2) | has | has | has | has | has |
| 3 | Debugger detection | planned (P2) | has | has | has | has | has |
| 4 | Hooking detection (Frida/Xposed) | planned (P2) | has | has | has | has | has |
| 5 | Environment risk (root/jailbreak/emulator) | planned (P2) | has | has | has | has | has |
| 6 | Network manipulation (MITM/proxy) | planned (P2) | has | has | partial | has | has |
| 7 | API request proof (per-request binding) | planned (P1) | partial | partial | partial | partial | partial |
| 8 | Secret protection (no static secrets) | planned (P1, design) | partial | partial | has | has | partial |
| 9 | Privacy guard (drop disallowed at source) | planned (P1) | missing | partial | missing | partial | partial |

**Reading this table:** modules 1–6 are table stakes the whole market has; kseal
*plans* them in P2 and does not claim them yet. The differentiators are module 7
(per-request cryptographic proof bound to *instance + build hash + risk + nonce +
policy*) and module 9 (an explicit, source-level data-minimization control) —
both areas where incumbents are only partial because their model is
client-decision-centric, not privacy-first.

---

## Build-Time Hardening

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| No-code / no-source wrapping | partial (plugin-based) | has | has | partial | has | partial |
| Source/IR-level obfuscation | planned (P3) | partial | partial | has | has | partial |
| String / resource / symbol encryption | planned (P3) | has | has | has | has | has |
| Native (.so / Mach-O) hardening | planned (P3) | has | has | has | has | has |
| Per-build polymorphism | planned (P3) | partial | partial | has | partial | partial |
| R8-compatible (mapping-aware) integration | planned (P3) | partial | partial | has | partial | partial |
| CFI / MTE for native | planned (P3) | missing | partial | partial | partial | missing |
| Avoids heavy VM obfuscation (by design) | has (design) | n/a | n/a | n/a | n/a | n/a |
| Runs in tenant CI (no per-build cloud compute) | planned (P3) | missing | missing | has | partial | missing |

Guardsquare is the build-hardening leader (its heritage is ProGuard/DexGuard).
kseal does not try to out-obfuscate Guardsquare; it deliberately
[avoids heavy VM obfuscation](../ARCHITECTURE.md#what-to-avoid) and competes on
**local-CI execution** (no per-build cloud cost) + **mapping-aware R8
compatibility** + **polymorphism feeding a decaying-bypass server model**.

---

## API Attestation & Backend Trust

This is kseal's wedge. The column that matters is whether the vendor ships a
**coherent server-side trust decision**, not just client checks plus a verdict
upload.

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| Play Integrity verification (server-side) | planned (P1) | partial | has | partial | partial | partial |
| App Attest / DeviceCheck verification (server-side) | planned (P1) | partial | has | partial | partial | partial |
| kseal trust-session protocol (own attestation) | planned (P1) | missing | partial | missing | partial | missing |
| Short-lived trust token (instance+build+risk+nonce+policy) | planned (P1) | missing | missing | missing | missing | missing |
| Signed per-request proof (hardware-bound) | planned (P1) | missing | partial | missing | partial | missing |
| Server-side authoritative enforcement | planned (P1) | partial | partial | partial | partial | partial |
| Replay/repack detectable server-side | planned (P1) | partial | partial | partial | partial | partial |
| Policy simulator (replay traffic vs policy) | planned (P2) | missing | partial | missing | missing | partial |
| No launch-time network call (perf budget) | planned (P1) | n/a | n/a | n/a | n/a | n/a |

The **trust token bound to instance + build hash + risk + nonce + policy** and a
**hardware-bound per-request proof** are not standard productized features
anywhere in the incumbent set — most stop at "run platform attestation and read
the verdict." That gap is the
[Strategic Position](../PROPOSAL.md#strategic-position) kseal is built on.

---

## Privacy

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| No raw PII collected | planned (P1) | partial | partial | partial | partial | partial |
| No cross-tenant device fingerprint | planned (P1) | missing | missing | partial | partial | missing |
| Tenant-scoped rotating identifiers | planned (P1) | missing | missing | missing | missing | missing |
| Compact, minimized event design | planned (P1) | partial | partial | partial | partial | partial |
| Source-level data-minimization (privacy guard) | planned (P1) | missing | partial | missing | partial | partial |
| Aggregates by default; raw opt-in | planned (P1) | partial | partial | partial | partial | partial |
| Machine-readable SDK data contract | planned (P1) | missing | missing | missing | missing | missing |

Privacy is where kseal is most differentiated. Zimperium in particular carries a
**heavier device-side telemetry footprint** (its MTD heritage), and most
incumbents have **no cross-tenant-fingerprint guarantee or rotating tenant-scoped
IDs**. kseal treats privacy as a
[design constraint](../ARCHITECTURE.md#privacy-architecture), not a setting.

---

## Compliance & Evidence

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| MASVS-anchored coverage (open standard) | planned (P1+) | partial | partial | partial | partial | partial |
| Auto-generated MASVS evidence report | planned (P3) | missing | partial | partial | missing | missing |
| MASTG-based verification procedures | planned (P0+) | missing | missing | partial | missing | missing |
| iOS privacy manifest generator | planned (P1) | missing | partial | missing | missing | missing |
| Google Data Safety helper | planned (P1) | missing | partial | missing | missing | missing |
| Audit trail / data-processing registry | planned (P1/P4) | partial | partial | partial | partial | partial |
| Regional retention controls | planned (P4) | partial | partial | partial | partial | partial |

Incumbents typically map to *their own* checklists; kseal anchors to the
**open, vendor-neutral [OWASP MASVS](https://mas.owasp.org/MASVS/)** and ships
**auto-generated evidence + store-disclosure artifacts**, which the
[NoOps](../PROPOSAL.md#noops-product-experience) model makes self-service.

---

## Enterprise Features

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| Multi-tenant logical isolation (`tenant_id`) | planned (P1) | partial | partial | partial | partial | partial |
| Multi-region data plane | planned (P4) | partial | partial | partial | partial | has |
| Dedicated / regulated isolation tier | planned (P4) | partial | partial | partial | has | has |
| Customer-managed keys (CMK / BYOK) | planned (P4) | missing | partial | partial | partial | partial |
| Private link / on-prem verifier | planned (P4) | missing | partial | partial | has | partial |
| Self-service onboarding (NoOps) | planned (P1) | has | partial | partial | missing | missing |
| Vertical policy packs (fintech/gaming/health/media) | planned (P4) | partial | partial | missing | partial | partial |
| Canary rollout + auto-rollback | planned (P2) | missing | partial | missing | missing | partial |
| Automatic false-positive detection | planned (P2) | missing | partial | missing | missing | partial |
| Signed kill switch (remote disable) | planned (P1) | partial | partial | partial | partial | partial |
| Self-service SIEM templates | planned (P2) | partial | partial | partial | missing | has |

kseal aims to combine **enterprise isolation** (CMK, private link, regulated
tier — typically Promon/Zimperium strengths) with **AppSealing-style self-service
NoOps**, a combination no single incumbent offers per the
[net implication](../PROPOSAL.md#market-analysis).

---

## Desktop

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| macOS code-integrity / notarization checks | planned (P5) | missing | partial | partial | partial | partial |
| Windows Authenticode / PE integrity | planned (P5) | missing | partial | partial | partial | partial |
| Desktop API attestation / trust session | planned (P5) | missing | missing | missing | partial | missing |
| Dylib / DLL injection detection | planned (P5) | missing | partial | partial | has | partial |
| TPM / Keychain-bound request proofs | planned (P5) | missing | missing | missing | partial | missing |
| Secure-update integration | planned (P5) | missing | partial | partial | partial | partial |

Desktop is the latest phase ([P5](../PROGRESS.md#phase-5-desktop-6-months-after-mobile-maturity))
and deliberately starts with **API attestation + code integrity + secure update**
and defers aggressive anti-debug
([Desktop caution](../ARCHITECTURE.md#desktop-caution)). The differentiator is
extending the **same trust-session backbone** to desktop, which the mobile-first
incumbents largely do not productize.

---

## Where kseal Wins, Matches, and Trails

A candid summary for planning:

| Dimension | Verdict | Why |
|---|---|---|
| **Server-side trust binding** | **Wins** | Trust token + per-request proof bound to instance/build/risk/nonce/policy — not a productized incumbent feature |
| **Privacy** | **Wins** | Rotating tenant-scoped IDs, no cross-tenant fingerprint, source-level minimization, data contract |
| **Open-standard evidence** | **Wins** | MASVS/MASTG anchoring + auto-generated evidence + store artifacts |
| **NoOps + enterprise isolation together** | **Wins** | Self-service *and* CMK/private-link/regulated tier in one product |
| **Lightweight footprint / unit cost** | **Wins (by design)** | < 40 ms startup, no launch network, compact telemetry, local-CI builds |
| **Classic RASP detections (1–6)** | **Matches (once P2 ships)** | Same detections as incumbents; advantage is server-side fusion, not the detections themselves |
| **Build-time obfuscation depth** | **Trails Guardsquare** | kseal avoids heavy VM obfuscation on purpose; competes on polymorphism + decay, not raw obfuscation strength |
| **MTD breadth / threat intel** | **Trails Zimperium** | kseal is app-trust-focused, not a mobile-threat-defense suite |
| **Maturity / track record** | **Trails all** | kseal is pre-P1; incumbents are shipping products. Honest near-term gap. |

The strategic conclusion mirrors [Go-to-Market](../PROPOSAL.md#go-to-market):
**lead with API trust + privacy** (where kseal wins outright and incumbents are
weakest), then add RASP (P2) and hardening (P3) to reach parity on the table
stakes — never trying to beat Guardsquare at obfuscation or Zimperium at MTD
breadth, because those are not the wedge.

See also: [threat-model.md](threat-model.md),
[masvs-mapping.md](masvs-mapping.md), and the [cost-model.md](cost-model.md) for
the economics behind the "lightweight / lower operating cost" wins.
