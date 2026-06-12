# kseal — Business & Product Proposal

## Table of Contents

- [Executive Summary](#executive-summary)
- [Strategic Position](#strategic-position)
- [Market Analysis](#market-analysis)
- [Standards Baseline](#standards-baseline)
- [Product Vision](#product-vision)
- [Differentiation Thesis vs AppSealing](#differentiation-thesis-vs-appsealing)
- [NoOps Product Experience](#noops-product-experience)
- [Unit Economics](#unit-economics)
- [Tenant Isolation Tiers](#tenant-isolation-tiers)
- [Risk Assessment](#risk-assessment)
- [Go-to-Market](#go-to-market)
- [Pricing Model Direction](#pricing-model-direction)

---

## Executive Summary

kseal is a **continuous app trust platform**, not an app-wrapping product. The distinction matters commercially and technically: wrappers sell a one-time transformation of a binary and are valued on how hard the resulting binary is to crack. kseal sells an ongoing trust relationship between an app instance and a backend, valued on whether the backend can *keep* distinguishing legitimate traffic from abuse over time.

The first defensible product is deliberately narrow and high-value:

> **Only legitimate, untampered, policy-compliant app instances can access protected APIs. Runtime threats are detected locally, scored privately, and enforced server-side.**

This framing wins because it attacks the failure mode every client-only competitor shares — the attacker owns the device — by moving the decision to infrastructure the attacker does not own. It also produces immediate, measurable business value (fewer fraudulent API calls, fewer fake clients, fewer repackaged-app installs hitting production) without requiring the customer to first re-architect their build pipeline.

---

## Strategic Position

kseal's strategy rests on five pillars delivered together rather than à la carte:

1. **Build-time hardening** — per-build polymorphic obfuscation and anti-tamper that raises reverse-engineering cost and prevents trivial repackaging.
2. **On-device runtime protection (RASP)** — local probes for root/jailbreak, debuggers, hooking frameworks, emulators, and network manipulation.
3. **Server-side attestation** — platform attestation (Play Integrity, App Attest) plus kseal's own trust-session protocol, verified on the backend.
4. **Privacy-preserving telemetry** — compact, minimized, tenant-scoped signals with no raw PII and no cross-tenant fingerprinting.
5. **Policy-based enforcement** — server-side decisions (`observe`, `step-up`, `block`) driven by tenant policy, with simulation and guardrails.

The anchor standard is **[OWASP MASVS](https://mas.owasp.org/MASVS/)** — open, testable, and vendor-neutral — rather than a proprietary vendor checklist. This lets customers map kseal coverage to an external benchmark their own security teams and auditors already trust.

---

## Market Analysis

The mobile app protection market is mature but fragmented, with most vendors anchored to a single pillar. The table below summarizes incumbent positioning and the implication for kseal.

| Vendor | Positioning | Strengths | Gaps / implication for kseal |
|---|---|---|---|
| **AppSealing / DoveRunner** | No-code RASP + app shielding, SaaS dashboard | Easy onboarding, real-time threat dashboard, runtime protection | Client-centric; limited backend trust binding and privacy story. **kseal differentiates on server-side enforcement + privacy + MASVS evidence.** |
| **Appdome** | No-code mobile defense automation, huge feature catalog | Very broad feature menu, CI/CD automation, no source changes | Breadth without a unified backend trust decision; feature sprawl. **kseal differentiates on a coherent trust-session model + lightweight footprint.** |
| **Guardsquare (DexGuard / iXGuard)** | Code hardening + obfuscation + RASP | Best-in-class obfuscation, polymorphism, threat monitoring | Strong client hardening, weaker server-side API attestation product. **kseal differentiates on API attestation + privacy-preserving telemetry.** |
| **Promon SHIELD** | In-app protection / RASP, OEM and fintech focus | Mature anti-tamper, app-shielding pedigree | Client-only enforcement model; less self-service. **kseal differentiates on NoOps self-service + backend enforcement.** |
| **Zimperium** | Mobile threat defense (MTD) + in-app protection (zDefend/zShield) | Threat intelligence, MTD breadth, enterprise sales motion | Heavier device-side footprint and telemetry; enterprise-sales-led. **kseal differentiates on lightweight, privacy-first, self-service economics.** |

**Net implication:** no incumbent simultaneously delivers (a) backend trust enforcement, (b) a privacy-first telemetry design, (c) MASVS-anchored evidence, and (d) NoOps self-service at lightweight cost. That intersection is kseal's wedge.

---

## Standards Baseline

kseal measures itself against **OWASP MASVS** coverage areas and verifies controls using the **OWASP MASTG**:

| MASVS area | Scope |
|---|---|
| **MASVS-STORAGE** | Secure local storage; no sensitive data in logs, caches, or backups. |
| **MASVS-CRYPTO** | Current algorithms, hardware-backed keys, correct key lifecycle. |
| **MASVS-AUTH** | Authentication and authorization, including step-up flows. |
| **MASVS-NETWORK** | TLS configuration, certificate handling, MITM resistance. |
| **MASVS-PLATFORM** | Safe IPC, WebView, permission, and deep-link handling. |
| **MASVS-CODE** | Dependency hygiene, secure defaults, code quality. |
| **MASVS-RESILIENCE** | Obfuscation, anti-debug, anti-tamper. |
| **MASVS-PRIVACY** | Data minimization, transparency, user control. |

**MASVS-RESILIENCE framing.** kseal treats obfuscation, anti-debug, and anti-tamper explicitly as **defense-in-depth** — controls that *raise attacker cost and slow bypass*, not controls that make the client unbreakable. This honest framing matters: it sets correct customer expectations, aligns with how OWASP itself describes resilience, and reinforces the core thesis that the authoritative trust decision lives server-side.

---

## Product Vision

The full kseal product spans seven feature domains:

- **Runtime protection (RASP):** root/jailbreak, emulator/simulator, debugger, hooking-framework, environment-risk, and network-manipulation detection, with local risk scoring.
- **Build-time hardening:** obfuscation, string/resource/symbol encryption, native library hardening, and per-build polymorphism via Gradle/Xcode plugins.
- **API attestation:** Play Integrity + App Attest verification, kseal trust sessions, short-lived trust tokens, and per-request signed proofs.
- **Privacy:** minimized compact events, tenant-scoped rotating IDs, no raw PII, automated store-disclosure artifacts.
- **Compliance:** MASVS evidence reports, audit trails, data-processing registry, regional retention controls.
- **Enterprise scale:** multi-region data plane, dedicated tenant tiers, customer-managed keys, private link, on-prem verifier, MSSP/partner console.
- **Desktop expansion:** macOS and Windows SDKs with code integrity, API attestation, and secure-update integration.

---

## Differentiation Thesis vs AppSealing

AppSealing is the closest "no-code RASP SaaS" comparator. kseal must make each differentiation claim *true*, not just marketed. The table pairs each claim with the concrete engineering work that backs it.

| Claim | How kseal makes it true |
|---|---|
| **More comprehensive** | Ship the full lifecycle: hardening + RASP + API attestation + privacy + MASVS evidence + SIEM + CI gates + policy sim + desktop — not just RASP. |
| **More robust** | Authoritative decision is server-side; trust tokens are short-lived; keys are hardware-backed; builds are polymorphic so a crack decays. |
| **More secure** | No static secrets in the binary; API access is bound to *app instance + build hash + risk state + nonce + server policy*; replays/repacks are server-detectable. |
| **More private** | No cross-tenant fingerprint; no raw PII; tenant-scoped rotating IDs; event minimization; automated iOS/Android disclosure artifacts. |
| **More lightweight** | Lazy + risk-driven checks; compact protobuf+zstd telemetry; CDN config; optional modules; **no launch-time network call**. |
| **Lower operating cost** | Build transforms run locally (no per-build cloud compute); sparse, batched, sampled, compressed telemetry; hot/cold retention; edge rejection. |
| **NoOps** | Self-service onboarding; vertical policy packs; policy simulator; canary + auto-rollback; automatic false-positive detection; signed remote config; CI templates; MASVS + privacy artifacts; self-service SIEM. |

---

## NoOps Product Experience

### Developer journey

| Time | Outcome |
|---|---|
| **15 min** | Create tenant, register app, install SDK, see a test-mode risk event. |
| **1 hr** | Add API attestation + signed request proof to one sensitive endpoint. |
| **1 day** | Add the hardening plugin, ship a protected staging build. |
| **1 week** | Tune via policy simulator, add CI gate, light up dashboards + SIEM. |
| **Ongoing** | Automatic updates, false-positive guardrails, per-release diff reports. |

### Must-have NoOps features

- **Policy packs by vertical** (fintech, gaming, health, media) — sensible defaults out of the box.
- **Test mode** — observe-only, never blocks, so teams build confidence before enforcing.
- **Policy simulator** — replay historical traffic against a candidate policy to see what *would* have been blocked.
- **Canary rollout** — stage policy/SDK changes to a fraction of traffic with automatic rollback.
- **Automatic false-positive detection** — flag policies that block anomalously high legitimate volume.
- **Per-build compatibility score** — predict integration risk before a build ships.
- **SDK crash/ANR monitoring** — treat SDK stability as a release gate.
- **Kill switch** — instantly disable enforcement or a module via signed remote config.
- **Signed remote config** — all config/policy is signed; the device rejects unsigned or stale config.
- **CI templates** — drop-in GitHub Actions / GitLab CI / Bitrise snippets.
- **MASVS evidence report** — auto-generated per release.
- **Privacy disclosure artifacts** — iOS privacy manifest + Google Data Safety helpers.
- **Self-service SIEM** — Splunk/Sentinel/Elastic templates, no PS engagement.
- **Human support only for enterprise exceptions** — everything else is self-serve.

---

## Unit Economics

The economic model lives or dies on telemetry volume. The design target is **sparse, compressed, sampled** events.

### Event math

Assume a large tenant: **100M MAU**, **30M DAU**.

| Design | Events/user/day | Bytes/event | Daily volume |
|---|---|---|---|
| **kseal (good design)** | 2 | 250 | 30M × 2 × 250 B ≈ **15 GB/day** |
| **Naive (bad design)** | ~20 (heartbeats + raw) | ~500 | **~300 GB/day** |

A ~20× difference in raw ingest compounds across storage, compression, query, egress, and retention. The good-design number (15 GB/day before compression) is what makes 100M-MAU pricing viable; the naive number is what makes competitors expensive or forces them to charge for basic telemetry.

### Cost-control rules

- **No heartbeat.** Protection is risk-driven and event-driven, never a fixed keepalive.
- **No raw telemetry by default.** Aggregates by default; raw events are an opt-in paid feature.
- **No attestation on every call.** Attest on sensitive actions and cache trust sessions.
- **CDN-served config.** Config is cacheable and signed; it does not hit origin per launch.
- **Batch events.** Coalesce and defer; never one request per event.
- **zstd dictionaries.** Shared dictionaries make tiny protobuf batches compress hard.
- **Sampling.** Sample low-severity/high-volume event classes.
- **Edge rejection.** Drop malformed/over-quota/unauthenticated traffic at the edge before it costs anything downstream.
- **Hot/cold retention.** Recent data in hot store (ClickHouse), older data in cheap object storage.
- **Raw data as a paid feature.** Customers who want full-fidelity retention pay for the storage they consume.
- **Local build transforms.** Hardening runs in the tenant's CI, so kseal incurs no per-build cloud compute.

---

## Tenant Isolation Tiers

kseal uses logical isolation by default and escalates physical isolation only where regulation or scale demands it (see [ARCHITECTURE.md](ARCHITECTURE.md#tenant-isolation)).

| Tier | Compute | Data | Keys / network |
|---|---|---|---|
| **Starter** | Shared | Shared (logical, `tenant_id`) | Logical isolation |
| **Growth** | Shared | Partitioned | Dedicated per-tenant keys |
| **Enterprise** | Dedicated partitions | Dedicated partitions + quotas | Region pinning |
| **Regulated** | Dedicated cluster | Dedicated cluster | Private link + customer-managed keys (CMK) + optional on-prem verifier |

---

## Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| **iOS App Review rejection** | High | No private/undocumented API use; App Attest/DeviceCheck only; App Review safety review in Phase 0; privacy manifest auto-generated. |
| **False positives blocking real users** | High | Default `observe → step-up → block`; policy simulator; canary + auto-rollback; automatic false-positive detection; kill switch. |
| **RASP bypass arms race** | Medium | Server-side enforcement so a client bypass decays; per-build polymorphism; signal fusion; rapid signed config updates. |
| **SDK performance regressions** | Medium | Hard performance budgets enforced in CI; crash/ANR release gate; lazy/risk-driven scheduling. |
| **Privacy backlash** | High | No raw PII; no cross-tenant fingerprint; minimized events; transparent disclosure artifacts; data-processing registry. |
| **Play Integrity quota exhaustion** | Medium | Attest only on sensitive actions; cache trust sessions; 10K/day default quota respected; request increases proactively. |
| **Enterprise support burden** | Medium | NoOps self-service; human support reserved for enterprise exceptions; policy packs reduce ticket volume. |
| **Build pipeline breakage** | Medium | Per-build compatibility score; staging-first rollout; CI templates; reversible plugin steps. |
| **Analytics cost explosion** | High | Sparse/sampled/compressed telemetry; aggregates by default; hot/cold retention; raw data as a paid feature. |

---

## Go-to-Market

Start with **API trust + privacy-preserving runtime telemetry**, *not* full app shielding. Rationale:

- **Lower compatibility risk.** An SDK + backend verification integrates without touching the customer's build pipeline or obfuscation config, so it rarely breaks builds.
- **Faster enterprise value.** Customers see fraudulent/fake-client traffic blocked on real endpoints within hours, a concrete and measurable win.
- **Stronger security foundation.** Establishing server-side trust first means every later feature (RASP, hardening) feeds a decision engine that already exists, rather than bolting enforcement on afterward.

App shielding and build-time hardening follow once the trust backbone and customer confidence are established.

---

## Pricing Model Direction

Pricing aligns with the cost drivers and value delivered:

- **MAU / MAD-based** — primary axis; tracks the population of protected app instances.
- **Event-based** — usage component for telemetry volume beyond included tiers.
- **Retention-based** — raw event retention and extended history priced as a paid add-on.

This keeps the base offering affordable (aggregates + standard retention) while letting heavy users pay for the full-fidelity data and long retention they specifically consume — directly mirroring the [unit economics](#unit-economics).
