# kseal — Feature Parity Matrix

A feature-by-feature comparison of **kseal** against the incumbents identified in
the [Market Analysis](../PROPOSAL.md#market-analysis): **AppSealing**
(DoveRunner), **Appdome**, **Guardsquare** (DexGuard / iXGuard), **Promon**
(SHIELD), and **Zimperium** (zDefend / zShield).

The intent is honest positioning, not marketing inflation: for kseal, a cell is
only **has** if the corresponding control is actually implemented and shipped on
`main`; capabilities still on the [roadmap](../PROGRESS.md) are marked **planned**
with their phase. The kseal column has been refreshed against the code in
`server/`, `sdk/`, `plugins/`, `cmd/`, and `deploy/` — each **has** below cites
the directory or document that implements it. The
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
> before competitive use. Only the **kseal** column is maintained against the
> current codebase.

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
| 1 | App integrity (repack/resign) | has | has | has | has | has | has |
| 2 | Runtime tamper (in-memory patch) | has | has | has | has | has | has |
| 3 | Debugger detection | has | has | has | has | has | has |
| 4 | Hooking detection (Frida/Xposed) | has | has | has | has | has | has |
| 5 | Environment risk (root/jailbreak/emulator) | has | has | has | has | has | has |
| 6 | Network manipulation (MITM/proxy) | has | has | has | partial | has | has |
| 7 | API request proof (per-request binding) | has | partial | partial | partial | partial | partial |
| 8 | Secret protection (no static secrets) | partial | partial | partial | has | has | partial |
| 9 | Privacy guard (drop disallowed at source) | has | missing | partial | missing | partial | partial |

**Implemented in:** detectors ship on every platform —
`sdk/android/src/main/kotlin/io/kseal/sdk/probes/` (`RootDetector`,
`EmulatorDetector`, `DebuggerDetector`, `HookDetector`, `IntegrityChecker`,
`NetworkRiskDetector`) and `sdk/ios/Sources/KsealSDK/` (`JailbreakDetector`,
`SimulatorDetector`, `DebuggerDetector`, `HookDetector`, `IntegrityChecker`,
`NetworkRiskDetector`), with the shared signal set in
`sdk/rust-core/kseal-core/src/risk.rs` (`ROOT`/`JAILBREAK`/`EMULATOR`/`DEBUGGER`/
`HOOKING`/`TAMPER`/`APP_INTEGRITY`/`NETWORK_MITM`/`PROXY`/`REPACKAGED`). Module 7
is the per-request proof in `sdk/rust-core/kseal-core/src/crypto.rs` +
`server/shared/proof/`. Module 9 is the on-device `PrivacyGuard`
(`sdk/rust-core/kseal-core/src/events.rs`).

**Reading this table:** modules 1–6 are table stakes the whole market has, and
kseal now ships the detections on Android, iOS and desktop. The differentiators
remain module 7 (per-request cryptographic proof bound to *instance + build hash
+ risk + nonce + policy*) and module 9 (an explicit, source-level
data-minimization control) — both areas where incumbents are only partial because
their model is client-decision-centric, not privacy-first. Module 8 stays
**partial**: kseal carries **no static secrets in the SDK** and binds the
per-request proof to a hardware-backed key (Android Keystore / iOS Keychain), but
it does not ship a general white-box / in-app secret-vault module, so it does not
claim full parity with Guardsquare/Promon there.

---

## Build-Time Hardening

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| No-code / no-source wrapping | partial (plugin-based) | has | has | partial | has | partial |
| Source/IR-level obfuscation | partial | partial | partial | has | has | partial |
| String / resource / symbol encryption | has | has | has | has | has | has |
| Native (.so / Mach-O) hardening | has | has | has | has | has | has |
| Per-build polymorphism | has | partial | partial | has | partial | partial |
| R8-compatible (mapping-aware) integration | has | partial | partial | has | partial | partial |
| CFI / MTE for native | has | missing | partial | partial | partial | missing |
| Avoids heavy VM obfuscation (by design) | has (design) | n/a | n/a | n/a | n/a | n/a |
| Runs in tenant CI (no per-build cloud compute) | has | missing | missing | has | partial | missing |

**Implemented in:** the Gradle plugin `plugins/gradle/src/` (`StringHardener`/
`ResourceHardener`, `HardenNativeLibrariesTask` + `ElfInspector` for CFI/MTE,
`GeneratePolymorphismSeedTask` + `SeedDeriver`, `KeepRules` + `MappingFile` +
`MappingComposer` for mapping-aware R8) and the Xcode/SwiftPM plugin
`plugins/xcode/Sources/` (`StringHardener`, `SymbolHardener`, `MachOInspector`,
`PolymorphismSeed`). Both run inside the tenant's own Gradle/Xcode build — there is
no per-build cloud compute. See [build-hardening-android.md](build-hardening-android.md)
and [build-hardening-ios.md](build-hardening-ios.md).

The GA polish in this wave makes both plugins **deterministic and reproducible**:
given identical inputs (same sources, same pinned seed) the hardened output is
byte-for-byte identical, asserted by cross-build functional tests on both
platforms. A misconfigured option (an unknown obfuscation strength, a malformed
pinned seed) now **fails the build loudly** with an actionable message rather
than silently weakening protection. Every shipped artifact's native posture
(RELRO+BIND_NOW, NX, PIE, stack-canary, FORTIFY, plus CFI/MTE/BTI/PAC) is
verified across `aarch64`/`arm`/`x86_64`/`x86` and recorded in the
`kseal.build-proof` manifest, whose v2 sections add an auditable `hash_coverage`
(an independent `artifacts_root` digest a verifier can recompute) and an explicit
`reproducibility` posture — every option is documented in
[plugins/gradle/README.md](../plugins/gradle/README.md).

Guardsquare is still the build-hardening leader (its heritage is ProGuard/
DexGuard). kseal deliberately
[avoids heavy VM obfuscation](../ARCHITECTURE.md#what-to-avoid): it ships string/
resource/symbol encryption, native hardening, per-build polymorphism and
mapping-aware R8, but **does not ship a Guardsquare-class source/IR obfuscator** —
hence those two rows stay **partial**. kseal competes on **local-CI execution**
(no per-build cloud cost) + **mapping-aware R8 compatibility** + **polymorphism
feeding a decaying-bypass server model** + **reproducible, build-proof-attested
output**, not on raw obfuscation depth.

---

## API Attestation & Backend Trust

This is kseal's wedge. The column that matters is whether the vendor ships a
**coherent server-side trust decision**, not just client checks plus a verdict
upload.

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| Play Integrity verification (server-side) | has | partial | has | partial | partial | partial |
| App Attest / DeviceCheck verification (server-side) | has | partial | has | partial | partial | partial |
| kseal trust-session protocol (own attestation) | has | missing | partial | missing | partial | missing |
| Short-lived trust token (instance+build+risk+nonce+policy) | has | missing | missing | missing | missing | missing |
| Signed per-request proof (hardware-bound) | has | missing | partial | missing | partial | missing |
| Server-side authoritative enforcement | has | partial | partial | partial | partial | partial |
| Replay/repack detectable server-side | has | partial | partial | partial | partial | partial |
| Policy simulator (replay traffic vs policy) | has | missing | partial | missing | missing | partial |
| Population/fleet-level anomaly detection (cohort baselines) | has | missing | partial | missing | missing | partial |
| Volume-velocity / coordinated-flood detection | has | missing | partial | missing | missing | partial |
| Per build/region cohort attack attribution | has | missing | missing | missing | missing | missing |
| No launch-time network call (perf budget) | has | n/a | n/a | n/a | n/a | n/a |

**Implemented in:** `server/data-plane/attestation/` (`play_integrity.go`,
`app_attest.go`, `verifier.go`), the trust-session protocol in
`server/data-plane/trust/` (`nonce.go` single-use anti-replay, `token.go`
short-lived trust token, `service.go` GetNonce/VerifyAttestation/
ValidateRequestProof), the canonical proof preimage in `server/shared/proof/`
mirrored by `sdk/rust-core/kseal-core/src/crypto.rs`, the decision mapping in
`server/shared/risk/risk.go` (`ALLOW`/`STEP_UP`/`DENY`), and the policy simulator
in `server/data-plane/simulator/` (also exposed via `kseal policy simulate` in
`cmd/kseal-cli/`).

The **trust token bound to instance + build hash + risk + nonce + policy** and the
**hardware-bound per-request proof** are now shipped and remain features the
incumbent set does not productize — most stop at "run platform attestation and
read the verdict." Replay is caught by single-use nonces; repackaging is caught by
the build-hash binding in the proof preimage. That gap is the
[Strategic Position](../PROPOSAL.md#strategic-position) kseal is built on.

Population-level abuse detection — the per-cohort baselines + volume-velocity
signal that Approov/Castle/Arkose monetize — ships in
`server/data-plane/fleet/` (**Fleet Anomaly Guard**): per-`(tenant, app, build,
region)` cohort baselines fuse a server-derived `FLEET_ANOMALY` bit into newly
joining clients on a surge, so the trust decision is no longer purely
per-instance and stateless (see [fleet-anomaly.md](fleet-anomaly.md)). The
device/wire and server risk-bit namespaces are unified by a single `risk.FromWire`
translation applied before fusion/scoring, pinned by Go + Rust contract tests
(see [risk-bit-contract.md](risk-bit-contract.md)).

---

## Privacy

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| No raw PII collected | has | partial | partial | partial | partial | partial |
| No cross-tenant device fingerprint | has | missing | missing | partial | partial | missing |
| Tenant-scoped rotating identifiers | has | missing | missing | missing | missing | missing |
| Compact, minimized event design | has | partial | partial | partial | partial | partial |
| Source-level data-minimization (privacy guard) | has | missing | partial | missing | partial | partial |
| Aggregates by default; raw opt-in | has | partial | partial | partial | partial | partial |
| Machine-readable SDK data contract | has | missing | missing | missing | missing | missing |

**Implemented in:** `sdk/rust-core/kseal-core/src/events.rs` — events carry **no
raw PII**, identity is reduced to a `tenant_scoped_install_key_hash` (a
tenant-scoped HMAC of the install key, never the raw install id, so the same
device under two tenants is unlinkable), timestamps are coarsened to buckets, and
the `PrivacyGuard` filter drops disallowed fields **on device** before anything
enters a batch. The data contract is **enforced, not just documented**:
`tests/privacy_contract_test.go` field-allowlists the `TelemetryEvent` and
`EventRecord` proto schemas and fails if any field falls outside the contract.
Aggregate-by-default storage with full-event opt-in is in
`server/data-plane/ingest/` (`writer.go`, `retention.go`) and the economics are in
[cost-model.md](cost-model.md).

Privacy is where kseal is most differentiated. Zimperium in particular carries a
**heavier device-side telemetry footprint** (its MTD heritage), and most
incumbents have **no cross-tenant-fingerprint guarantee or rotating tenant-scoped
IDs**. kseal treats privacy as a
[design constraint](../ARCHITECTURE.md#privacy-architecture), not a setting.

---

## Compliance & Evidence

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| MASVS-anchored coverage (open standard) | has | partial | partial | partial | partial | partial |
| Auto-generated MASVS evidence report | has | missing | partial | partial | missing | missing |
| MASTG-based verification procedures | partial | missing | missing | partial | missing | missing |
| iOS privacy manifest generator | has | missing | partial | missing | missing | missing |
| Google Data Safety helper | has | missing | partial | missing | missing | missing |
| Audit trail / data-processing registry | partial | partial | partial | partial | partial | partial |
| Regional retention controls | partial | partial | partial | partial | partial | partial |

**Implemented in:** the MASVS mapping in [masvs-mapping.md](masvs-mapping.md), the
auto-generated evidence report via the Gradle `GenerateMasvsReportTask`
(`plugins/gradle/src/`) and `kseal masvs` in `cmd/kseal-cli/internal/cli/masvs.go`
(report sample in [masvs-evidence.md](masvs-evidence.md)). Retention/purge controls
are in `server/data-plane/ingest/retention.go`; the queryable event read model
(`server/data-plane/query/`) provides an audit-style trail. The **iOS privacy
manifest generator** (`tools/privacy-manifest/`, emitting `PrivacyInfo.xcprivacy`
from the SDK's machine-readable data contract) and the **Google Data-Safety
helper** (`tools/datasafety/` + `kseal compliance` in
`cmd/kseal-cli/internal/cli/compliance.go`) generate store-submission disclosures
directly from that same contract — see [privacy-manifest.md](privacy-manifest.md)
and [data-safety.md](data-safety.md).

What stays honest here: **MASTG procedures are partial** (the mapping references
MASTG but kseal does not ship a full executable verification suite); the **iOS
privacy-manifest generator and Google Data-Safety helper now ship** (both derive
their output from the enforced SDK data contract rather than hand-maintained
lists); **audit trail is partial** (security-event query exists, but a formal
data-processing registry / ROPA does not); and **regional retention is partial**
(per-tenant retention/purge ships, region-scoping comes from the residency
topology rather than per-region retention knobs). kseal anchors to the open,
vendor-neutral [OWASP MASVS](https://mas.owasp.org/MASVS/) and ships
**auto-generated evidence**, which the
[NoOps](../PROPOSAL.md#noops-product-experience) model makes self-service.

---

## Enterprise Features

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| Multi-tenant logical isolation (`tenant_id`) | has | partial | partial | partial | partial | partial |
| Multi-region data plane | has | partial | partial | partial | partial | has |
| Dedicated / regulated isolation tier | has | partial | partial | partial | has | has |
| Customer-managed keys (CMK / BYOK) | has | missing | partial | partial | partial | partial |
| Private link / on-prem verifier | has | missing | partial | partial | has | partial |
| Self-service onboarding (NoOps) | has | has | partial | partial | missing | missing |
| Vertical policy packs (fintech/gaming/health/media) | has | partial | partial | missing | partial | partial |
| Canary rollout + auto-rollback | has | missing | partial | missing | missing | partial |
| Automatic false-positive detection | has | missing | partial | missing | missing | partial |
| Signed kill switch (remote disable) | has | partial | partial | partial | partial | partial |
| Self-service SIEM templates | has | partial | partial | partial | missing | has |

**Implemented in:** logical isolation via `server/shared/auth/` (`EnforceTenant`/
`WithPrincipal` + the row-level-security guard applied by every query); multi-region
topology in `deploy/terraform/modules/multi-region/` + region-scoped Helm releases
(see [multi-region.md](multi-region.md)); the regulated/dedicated tier via the
on-prem verifier (`deploy/onprem/`, [deployment-onprem.md](deployment-onprem.md))
and private link (`deploy/terraform/modules/private-link/`,
[deployment-private-link.md](deployment-private-link.md)); CMK/BYOK in
`server/shared/crypto/` (`kek.go`, `kms_http.go`) + `server/control-plane/registry/cmk.go`
([byok.md](byok.md)); the NoOps CLI in `cmd/kseal-cli/` (tenant/app/key lifecycle,
[cli.md](cli.md)); vertical policy packs in
`cmd/kseal-cli/internal/cli/packs_data/{fintech,gaming,health,media}.json`
([policy-packs.md](policy-packs.md)); false-positive detection in
`server/data-plane/guardrails/detector.go`; staged **canary rollout with
auto-rollback** in `server/data-plane/canary/` (`controller.go` reverts a
candidate cohort to the last-known-good policy when its guardrail block-rate
breaches threshold, `bucket.go` does the deterministic percentage bucketing,
`registry.go` tracks active canaries) — gated by `compliance.FlagCanaryRollout`
([canary-rollout.md](canary-rollout.md)); the **signed kill switch**
(`ksealv1.SignedKillSwitch`, resolved per app/build in
`server/data-plane/config/service.go` and delivered through the signed config
response, persisted in `server/control-plane/compliance/`) — gated by
`compliance.FlagKillSwitch` ([kill-switch.md](kill-switch.md)); and SIEM templates
(Elastic ECS, Splunk, Sentinel) in `server/data-plane/siem/templates/`
([siem-integration.md](siem-integration.md)).

Both **canary rollout + auto-rollback** and the **signed kill switch** now ship:
candidate policies roll out to a deterministic percentage cohort and auto-revert
to the last-known-good policy when the guardrails detector observes a block-rate
regression, and a cryptographically **signed**, app/build-scoped kill switch is
resolved server-side and delivered through the signed config response (so a
compromised build can be fenced off without shipping an app update). Both are
gated behind per-tenant feature flags for safe rollout.
kseal combines **enterprise isolation** (CMK, private link, regulated tier —
typically Promon/Zimperium strengths) with **AppSealing-style self-service NoOps**,
a combination no single incumbent offers per the
[net implication](../PROPOSAL.md#market-analysis).

---

## Desktop

| Capability | kseal | AppSealing | Appdome | Guardsquare | Promon | Zimperium |
|---|---|---|---|---|---|---|
| macOS code-integrity / notarization checks | has | missing | partial | partial | partial | partial |
| Windows Authenticode / PE integrity | has | missing | partial | partial | partial | partial |
| Desktop API attestation / trust session | has | missing | missing | missing | partial | missing |
| Dylib / DLL injection detection | has | missing | partial | partial | has | partial |
| TPM / Keychain-bound request proofs | has | missing | missing | missing | partial | missing |
| Secure-update integration | has | missing | partial | partial | partial | partial |

**Implemented in:** `sdk/desktop/macos/Sources/KsealDesktop/` (code-signature,
notarization and hardened-runtime probes, dylib-injection detection, and the
trust-session client + request proof in `TrustCore.swift`) and
`sdk/desktop/windows/src/Kseal.Desktop/` (`AuthenticodeProbe` via `WinVerifyTrust`,
`PeIntegrityProbe`, `DllInjectionProbe`, `DebuggerProbe`, and the trust-session
client). See [desktop-sdk.md](desktop-sdk.md).

The per-request proof key on desktop is now **bound to a hardware element where
the platform provides one** — the **macOS Keychain (Secure-Enclave-wrapped on
Apple silicon)** via `KeychainHardwareKeyStore`
(`sdk/desktop/macos/Sources/KsealDesktop/Security/HardwareKeyStore.swift`) and a
**Windows TPM through the CNG Platform Crypto Provider** via
`TpmHardwareKeyStore` (`sdk/desktop/windows/src/Kseal.Desktop/Security/HardwareKeyStore.cs`).
The proof-byte layout is unchanged (`HMAC(proofKey, …)`); only how `proofKey` is
protected at rest changes, so the sealed secret cannot be lifted and replayed
from another device. A clean software fallback keeps CI/virtualized hosts
working, and `isHardwareBacked` is surfaced so a policy can **require** hardware
binding and fail closed. **Secure-update integration** also ships
(`Update/SecureUpdate.{swift,cs}`, signature- and version-checked updates — see
[desktop-secure-update.md](desktop-secure-update.md)). Desktop deliberately
starts with **API attestation + code integrity** and defers aggressive anti-debug
([Desktop caution](../ARCHITECTURE.md#desktop-caution)). The differentiator is
extending the **same trust-session backbone** to desktop, which the mobile-first
incumbents largely do not productize.

---

## Where kseal Wins, Matches, and Trails

A candid summary for planning:

| Dimension | Verdict | Why |
|---|---|---|
| **Server-side trust binding** | **Wins** | Trust token + per-request proof bound to instance/build/risk/nonce/policy now ship (`server/data-plane/trust`, `server/shared/proof`) — not a productized incumbent feature |
| **Privacy** | **Wins** | Rotating tenant-scoped IDs, no cross-tenant fingerprint, on-device privacy guard, and an enforced machine-readable data contract |
| **Open-standard evidence** | **Wins** | MASVS anchoring + auto-generated evidence report (`GenerateMasvsReportTask`, `kseal masvs`) |
| **NoOps + enterprise isolation together** | **Wins** | Self-service CLI *and* CMK / private-link / on-prem / multi-region in one product |
| **Lightweight footprint / unit cost** | **Wins (by design)** | < 40 ms startup, no launch network, compact telemetry, local-CI builds |
| **Population-level abuse detection** | **Matches (NoOps edge)** | Fleet Anomaly Guard adds per-cohort baselines + volume-velocity to the server trust decision (`server/data-plane/fleet`); zero-config and flag-gated, where Castle/Arkose sell it as a tuned premium tier |
| **Classic RASP detections (1–6)** | **Matches** | Detections now ship on Android, iOS and desktop; advantage is server-side fusion, not the detections themselves |
| **Build-time obfuscation depth** | **Trails Guardsquare** | kseal ships string/symbol/native hardening + polymorphism but avoids heavy VM / source-IR obfuscation on purpose; competes on polymorphism + decay, not raw obfuscation strength |
| **MTD breadth / threat intel** | **Trails Zimperium** | kseal is app-trust-focused, not a mobile-threat-defense suite |
| **Maturity / track record** | **Trails all** | kseal's capabilities are newly shipped; the incumbents have years of production track record. Honest near-term gap. |

The strategic conclusion mirrors [Go-to-Market](../PROPOSAL.md#go-to-market):
**lead with API trust + privacy** (where kseal wins outright and incumbents are
weakest), with RASP detections and build hardening now shipped to match on the
table stakes — never trying to beat Guardsquare at obfuscation depth or Zimperium
at MTD breadth, because those are not the wedge.

See also: [threat-model.md](threat-model.md),
[masvs-mapping.md](masvs-mapping.md), and the [cost-model.md](cost-model.md) for
the economics behind the "lightweight / lower operating cost" wins.
