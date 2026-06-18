# kseal — Threat Model (by Vertical)

A STRIDE-based threat model for the four launch verticals kseal targets:
**fintech**, **gaming**, **health**, and **media**. It is grounded in the
four-plane architecture and the trust-session flow described in
[ARCHITECTURE.md](../ARCHITECTURE.md) and the product thesis in
[PROPOSAL.md](../PROPOSAL.md).

The unifying assumption — stated once and applied everywhere — is that **the
attacker owns the device**. Root, a hooking framework (Frida/Xposed/objection),
a disassembler, a patched OS, and an intercepting proxy are all available to the
adversary. kseal therefore models threats against the *system*, not the client
alone: the authoritative trust decision lives server-side, and on-device
controls are explicitly defense-in-depth that raise attacker cost (see
[MASVS-RESILIENCE framing](../PROPOSAL.md#standards-baseline)).

## Table of Contents

- [Scope and Method](#scope-and-method)
- [Trust Boundaries and Assets](#trust-boundaries-and-assets)
- [STRIDE Reference for kseal](#stride-reference-for-kseal)
- [Cross-Vertical Attack Trees](#cross-vertical-attack-trees)
- [Vertical: Fintech](#vertical-fintech)
- [Vertical: Gaming](#vertical-gaming)
- [Vertical: Health](#vertical-health)
- [Vertical: Media](#vertical-media)
- [Enforcement-Level Guidance](#enforcement-level-guidance)
- [Residual Risk and Non-Goals](#residual-risk-and-non-goals)

---

## Scope and Method

We use **STRIDE** (Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service, Elevation of privilege) applied at each trust boundary of the
[four-plane architecture](../ARCHITECTURE.md#system-overview). Per vertical we
document:

1. **Attacker profiles** — who attacks, their motivation, capability, and
   economic ceiling (how much an attack is worth to them).
2. **Assets at risk** — what the attacker is actually after.
3. **Attack trees** — the concrete paths from attacker goal to impact.
4. **Applicable RASP modules** — which of the nine
   [runtime modules](../ARCHITECTURE.md#rasp-probes) raise the
   cost of each path.
5. **Recommended enforcement level** — the default policy posture
   (`observe → step-up → block`) calibrated to that vertical's risk tolerance.

Likelihood/impact ratings are qualitative (**Low / Medium / High / Critical**)
and reflect the *post-mitigation* residual unless stated otherwise.

---

## Trust Boundaries and Assets

kseal's planes define five trust boundaries. Threats are enumerated where data
or authority crosses one.

| # | Boundary | Lower-trust side | Higher-trust side | Primary control |
|---|---|---|---|---|
| B1 | App ↔ OS | Untrusted device runtime | App process + Rust core | RASP probes, hardware-backed keys |
| B2 | Device ↔ Edge | Internet (attacker-controlled network) | Edge gateway / verifier | TLS + pinning, attestation, request proofs |
| B3 | Edge ↔ Data plane | Edge-terminated traffic | Ingest / risk engine | Signed artifacts, quotas, schema validation |
| B4 | Data plane ↔ Control plane | High-volume derived state | Source of truth (IAM, keys, policy) | KMS/HSM, signed config, no long-lived secrets in DP |
| B5 | Build plane ↔ Device | Tenant CI output | Runtime build-proof check | Build manifest + registered build hash |

**Assets at risk** (shared across verticals, weighted differently per vertical):

| Asset | Description |
|---|---|
| Protected API access | The right to call a tenant's sensitive endpoints. |
| Trust token | Short-lived credential binding instance + build hash + risk + nonce + policy. |
| Per-tenant key material | Signing/encryption keys; compromise breaks the proof chain. |
| Telemetry stream | Minimized risk events; integrity matters more than confidentiality. |
| Tenant policy / config | Signed rules that drive enforcement. |
| User account / session | The tenant's end-user identity behind the app. |
| Build proof registry | Mapping of legitimate build hashes to apps. |

---

## STRIDE Reference for kseal

This table is the reusable backbone the per-vertical sections specialize.

| STRIDE | Representative threat against kseal | Boundary | Primary mitigations |
|---|---|---|---|
| **Spoofing** | Fake/repackaged client impersonates a legitimate instance; emulator farm poses as real devices | B1, B2 | Platform attestation (Play Integrity / App Attest), app-integrity module, hardware-bound request proofs, trust tokens bound to build hash |
| **Tampering** | In-memory patching of checks; modified config; forged telemetry | B1, B3, B5 | Runtime-tamper + app-integrity probes, signed config (device rejects unsigned/stale), schema-validated ingest, build-proof check |
| **Repudiation** | Tenant or abuser disputes that a decision/event occurred | B3, B4 | Append-only audit log, decision provenance (token + nonce + policy version recorded), compliance registry |
| **Information disclosure** | Extraction of static secrets; cross-tenant correlation; PII leakage in telemetry | B1, B2, B4 | No static secrets (keys derived/hardware-bound), tenant-scoped rotating IDs, privacy guard drops disallowed signals at source, no raw PII |
| **Denial of service** | Telemetry flood, quota exhaustion (Play Integrity), trust-session storm | B2, B3 | Edge rejection + per-tenant quotas, attest-on-sensitive-action only + cached sessions, batched/sampled telemetry, fail-safe load shedding |
| **Elevation of privilege** | Replayed/stolen trust token used beyond scope; cross-tenant access | B2, B4 | Short-lived tokens + per-request nonce (replay-detectable), `tenant_id` logical isolation + per-tenant keys, row-level guards |

---

## Cross-Vertical Attack Trees

Three attack trees recur in every vertical; per-vertical sections reference them
by name (**AT-1**, **AT-2**, **AT-3**) and add domain-specific leaves.

### AT-1 — Forge a trusted client

```text
GOAL: Get the backend to treat an attacker-controlled client as trusted
├── 1. Repackage the legitimate app
│   ├── 1.1 Resign with attacker cert            [app-integrity: signing-cert mismatch]
│   ├── 1.2 Patch out RASP checks in DEX/Mach-O  [runtime-tamper: section checksum]
│   └── 1.3 Strip request-proof signing          [server: missing/invalid proof → deny]
├── 2. Run real app under instrumentation
│   ├── 2.1 Frida/Xposed hook the proof signer   [hooking-detection: high-weight signal]
│   └── 2.2 Emulator/simulator at scale          [environment-risk + attestation: device verdict]
└── 3. Defeat platform attestation
    ├── 3.1 Spoof Play Integrity verdict         [server verifies w/ Google; nonce binds request]
    └── 3.2 Reuse another device's App Attest key [key is hardware-bound; nonce/freshness checks]
```

Server-side fusion means a single bypassed leaf is insufficient: the trust token
is only minted when attestation **and** fused risk **and** policy all pass, and
it expires quickly so a one-time bypass does not become durable access.

### AT-2 — Replay or steal a trust token

```text
GOAL: Use a valid token outside its intended instance/time
├── 1. Capture token in transit                  [TLS + pinning; network-manipulation probe]
├── 2. Replay captured request                   [per-request nonce → replay detected server-side]
├── 3. Exfiltrate token from device storage      [token short-lived; bound to hardware key proof]
└── 4. Use token from a different instance        [proof requires hardware key; build-hash binding]
```

### AT-3 — Abuse telemetry / cost / availability

```text
GOAL: Degrade the service or inflate the tenant's bill
├── 1. Flood ingest with forged events           [edge rejection + per-tenant quota; schema validation]
├── 2. Exhaust Play Integrity 10K/day quota       [attest-on-sensitive-action only; cached sessions]
├── 3. Trust-session storm                        [rate limits; fail-safe shed; cheap edge reject]
└── 4. Poison aggregates with junk signals        [signed proofs gate event admission; sampling]
```

---

## Vertical: Fintech

Payments, banking, brokerage, crypto wallets, and lending apps. The defining
characteristic is **direct monetary value per successful fraud event** and the
heaviest regulatory load (PCI-DSS, PSD2/SCA, KYC/AML).

### Fintech — attacker profiles

| Profile | Motivation | Capability | Economic ceiling |
|---|---|---|---|
| **Organized fraud ring** | Account takeover, money movement, mule onboarding | High: device farms, automation, stolen-credential markets, custom Frida scripts | High — six/seven-figure programs |
| **Credential-stuffing operator** | Bulk ATO at scale | Medium: rotating proxies, headless/emulated clients | Medium |
| **Insider / compromised endpoint** | Bypass SCA, escalate limits | Medium: legitimate session + tampering | High per-incident |
| **Malware author** | Overlay/accessibility theft, transaction tampering | High: Android accessibility abuse, screen capture | High |

### Fintech — assets at risk (weighted)

Highest: **user account/session**, **protected API access** (payment/transfer
endpoints), **trust token**. Compromise maps directly to monetary loss and
regulatory exposure.

### Fintech — attack trees

- **AT-1 (forge client)** + leaf: *emulator farm + injected accessibility
  service* to script transfers. RASP: environment-risk, hooking-detection,
  app-integrity.
- **AT-2 (token replay)** + leaf: *MITM via user-installed CA on a managed
  device* to lift a SCA-step-up token. RASP: network-manipulation,
  request-proof.
- **New AT-F1 — defeat step-up (SCA bypass)**:

```text
GOAL: Move money without satisfying strong customer authentication
├── 1. Hook the SCA prompt to auto-confirm        [hooking-detection → step-up/block]
├── 2. Replay a prior step-up token               [nonce + short TTL → deny]
└── 3. Overlay attack to harvest OTP              [environment-risk + network signal → step-up]
```

### Fintech — applicable RASP modules and enforcement

| Concern | Modules | Enforcement |
|---|---|---|
| Repackaged/fake client | App integrity (1), runtime tamper (2) | **Block** on signing/build-hash mismatch |
| Instrumentation | Hooking (4), debugger (3) | **Step-up → block** on high-weight hook signal |
| Emulator/root | Environment risk (5) | **Step-up**; block for money-movement endpoints |
| MITM / overlay | Network manipulation (6) | **Step-up**; require fresh attestation |
| Transaction integrity | API request proof (7) | **Block** invalid/replayed proofs (hard) |

**Recommended enforcement level: STRICT.** Default still `observe → step-up →
block`, but money-movement endpoints graduate to enforcing `block` quickly after
canary, and request-proof failures are hard-blocked from day one. False
positives are mitigated by step-up (MFA) rather than lockout per
[Risk Assessment](../PROPOSAL.md#risk-assessment).

---

## Vertical: Gaming

Free-to-play and competitive mobile games. Value is **aggregate, not
per-event** — cheating and IAP fraud erode revenue and player trust at volume.
Tolerance for latency overhead is the lowest of any vertical.

### Gaming — attacker profiles

| Profile | Motivation | Capability | Economic ceiling |
|---|---|---|---|
| **Cheat developer** | Sell aimbots/wallhacks/speed hacks | High: memory editing, hooking, custom mods | Medium — monetized cheat market |
| **IAP fraudster** | Forge purchases / unlock paid content | Medium: receipt forgery, repackaged APKs | Medium |
| **Bot/farm operator** | Resource farming, RMT (real-money trading) | High: emulator farms, automation | Medium-High |
| **Casual modder** | Single-player advantage | Low: off-the-shelf modded APKs | Low |

### Gaming — assets at risk (weighted)

Highest: **protected API access** (score submission, IAP validation,
matchmaking), **game-state integrity**, **build-proof registry** (modded-APK
detection).

### Gaming — attack trees

- **AT-1 (forge client)** + leaf: *modded APK distributed via third-party
  store*. RASP: app-integrity, build-proof check (B5).
- **AT-3 (cost/abuse)** + leaf: *bot farm inflating reward endpoints*. RASP:
  environment-risk, server quotas.
- **New AT-G1 — runtime cheating**:

```text
GOAL: Gain unfair advantage in a live match
├── 1. Memory edit speed/health                   [runtime-tamper → risk signal]
├── 2. Hook RNG / input pipeline                  [hooking-detection → step-up]
└── 3. Spoof score on submission                  [request-proof binds payload → server rejects]
```

### Gaming — applicable RASP modules and enforcement

| Concern | Modules | Enforcement |
|---|---|---|
| Modded/repackaged APK | App integrity (1), build proof (B5) | **Block** unknown build hashes from ranked play |
| Cheats / memory edit | Runtime tamper (2), hooking (4) | **Observe → step-up** (shadow-ban friendly) |
| Bot farms | Environment risk (5), request proof (7) | Server-side **quota + block** on score endpoints |
| IAP fraud | App integrity (1), request proof (7) | **Block** unverifiable purchase proofs |

**Recommended enforcement level: BALANCED, latency-first.** Because the
[startup budget is < 40 ms](../ARCHITECTURE.md#performance-budgets) and gaming is
the most latency-sensitive vertical, checks are strictly lazy/risk-driven.
Anti-cheat favors **server-side shadow actions** (segregated matchmaking,
score-rejection) over client blocking to avoid frustrating legitimate players on
exotic-but-genuine devices. IAP and ranked submission proofs are hard-enforced.

---

## Vertical: Health

Telehealth, digital therapeutics, fitness/medical-record apps. Defining
characteristic is **sensitive PII/PHI** and regulation (HIPAA, GDPR special
category, regional health-data law). Confidentiality and data-minimization
dominate over fraud economics.

### Health — attacker profiles

| Profile | Motivation | Capability | Economic ceiling |
|---|---|---|---|
| **Data broker / exfiltrator** | Resell PHI | Medium-High: reverse-engineer storage/transport | High — PHI commands premium |
| **Curious/insider tenant abuser** | Cross-patient access | Medium: API enumeration | High per-incident (regulatory) |
| **Nation-state / targeted** | Surveillance of individuals | High | High |
| **Opportunistic malware** | Bulk PII theft | Medium | Medium |

### Health — assets at risk (weighted)

Highest: **user PHI/PII** (confidentiality), **telemetry stream** (must contain
no PHI), **per-tenant key material**, **session**. Note kseal itself is designed
to *not* hold raw PII; the threat here is largely about ensuring kseal never
becomes a PHI side-channel.

### Health — attack trees

- **New AT-H1 — turn telemetry into a PHI side-channel**:

```text
GOAL: Exfiltrate health data via the protection SDK
├── 1. Coax SDK into logging identifiers/PHI      [privacy guard (9) strips at source; no raw PII]
├── 2. Correlate users across tenants             [tenant-scoped rotating IDs → no linkage]
└── 3. Read raw IP / device fingerprint           [raw IP not persisted; fingerprinting disabled]
```

- **AT-2 (token replay)** + leaf: *MITM on a hostile clinic Wi-Fi*. RASP:
  network-manipulation, pinning.
- **AT-1 (forge client)** + leaf: *fake telehealth client harvesting records via
  API*. Server: attestation + per-tenant isolation.

### Health — applicable RASP modules and enforcement

| Concern | Modules | Enforcement |
|---|---|---|
| PHI leakage via telemetry | Privacy guard (9) | **Drop at source** (always on; non-optional) |
| Insecure storage of secrets | Secret protection (8) | Design-level: no static secrets, hardware-bound keys |
| MITM on clinical networks | Network manipulation (6) | **Step-up**; strict pinning |
| Fake client enumerating records | App integrity (1), request proof (7) | **Block** at API on invalid proof |
| Cross-tenant correlation | Privacy architecture | Enforced by `tenant_id` isolation + rotating IDs |

**Recommended enforcement level: STRICT on confidentiality, MODERATE on
availability.** Privacy guard and tenant-scoped IDs are non-negotiable. Because
locking a patient out of care has real harm, blocking favors **step-up over hard
lockout** for legitimate-but-risky environments, while clearly fraudulent
clients (failed attestation, invalid proof) are blocked. Regional retention
controls and the data-processing registry are mandatory for this vertical.

---

## Vertical: Media

Streaming video/audio, premium content, and subscription apps. Defining
characteristic is **content-licensing and entitlement abuse** at scale —
credential sharing, scraping, and stream ripping. Value is per-stream and
aggregate.

### Media — attacker profiles

| Profile | Motivation | Capability | Economic ceiling |
|---|---|---|---|
| **Pirate / ripper** | Capture and redistribute premium content | High: DRM probing, repackaging, capture tooling | Medium-High |
| **Credential-sharing service** | Resell shared accounts at scale | Medium: automation, rotating clients | Medium |
| **Scraper** | Bulk-harvest catalog/metadata | Medium: headless clients, API enumeration | Low-Medium |
| **Ad/measurement fraudster** | Inflate views/ad impressions | Medium-High: emulator/bot farms | Medium |

### Media — assets at risk (weighted)

Highest: **protected API access** (entitlement/license endpoints),
**user/session** (sharing), **telemetry integrity** (view-count/ad fraud).

### Media — attack trees

- **AT-1 (forge client)** + leaf: *headless/scripted client harvesting license
  tokens*. RASP: app-integrity, attestation.
- **AT-3 (abuse)** + leaf: *bot farm inflating ad/measurement events*. RASP:
  environment-risk, request-proof, server sampling/quota.
- **New AT-M1 — entitlement/credential sharing**:

```text
GOAL: Share one paid account across many uninstrumented clients
├── 1. Extract license token, replay elsewhere    [request-proof binds device; replay detected]
├── 2. Script many concurrent sessions            [environment-risk + concurrency policy server-side]
└── 3. Repackage app to strip entitlement checks  [app-integrity + build-proof → block]
```

### Media — applicable RASP modules and enforcement

| Concern | Modules | Enforcement |
|---|---|---|
| Stream ripping / repackage | App integrity (1), runtime tamper (2) | **Step-up → block** on tamper |
| Credential sharing | API request proof (7), environment risk (5) | Server-side **concurrency policy + step-up** |
| Scraping / enumeration | Request proof (7) | **Block/throttle** unauthenticated/over-quota at edge |
| Ad/view fraud | Environment risk (5), request proof (7) | **Sampling + server filtering**; reject forged events |

**Recommended enforcement level: BALANCED.** Media tolerates more latency than
gaming but less regulatory weight than fintech/health. Emphasis is on
**server-side entitlement decisions and edge throttling** rather than aggressive
client blocking, preserving the experience for legitimate viewers on smart-TV
casts, shared family devices, and varied networks.

---

## Enforcement-Level Guidance

A consolidated view of the default posture per vertical. All start from
`observe → step-up → block`; the table shows how aggressively each graduates and
where hard blocks apply from day one.

| Vertical | Default posture | Hard-block from day 1 | Graduation speed | Primary FP mitigation |
|---|---|---|---|---|
| **Fintech** | Strict | Invalid/replayed request proofs; failed attestation on money movement | Fast (after canary) | Step-up (MFA), simulator, kill switch |
| **Gaming** | Balanced, latency-first | IAP/ranked proof failures | Slow for cheats (shadow actions) | Segregated matchmaking, observe-mode |
| **Health** | Strict confidentiality, moderate availability | Invalid proof on record access | Medium | Step-up over lockout; privacy guard always on |
| **Media** | Balanced | Repackaged-build entitlement calls | Medium | Edge throttle, concurrency policy |

All four rely on the same guardrails from
[NoOps](../PROPOSAL.md#noops-product-experience): test mode, policy simulator,
canary + auto-rollback, automatic false-positive detection, and a signed kill
switch.

---

## Residual Risk and Non-Goals

Honest scoping per the [MASVS-RESILIENCE framing](../PROPOSAL.md#standards-baseline):

- **Client controls are bypassable given enough effort.** RASP raises cost and
  buys detection time; it is not a guarantee. The durable control is server-side
  enforcement + per-build polymorphism so a bypass decays.
- **kseal does not provide DRM.** Content protection (media) requires a DRM
  stack (Widevine/FairPlay); kseal complements it by attesting the client and
  gating license endpoints, not by encrypting content.
- **kseal does not replace SCA/KYC.** For fintech it strengthens the channel
  (anti-tamper, attestation, request proofs) but the regulated authentication
  factors remain the tenant's responsibility.
- **No behavioral profiling or cross-tenant fingerprinting** — by design (see
  [Privacy Architecture](../ARCHITECTURE.md#privacy-architecture)). This bounds
  certain fraud-correlation techniques in exchange for a defensible privacy
  posture, a deliberate trade-off.
- **Platform attestation has limits.** Play Integrity / App Attest verdicts can
  degrade (older devices, outages); policy must fail safe and lean on kseal's
  own signals + risk fusion rather than treating attestation as binary truth.

See also: [MASVS mapping](masvs-mapping.md),
[iOS App Review analysis](ios-app-review.md),
[Android policy review](android-policy-review.md).
