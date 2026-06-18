# kseal — MASVS Control Mapping

This document maps every kseal control to the
**[OWASP MASVS](https://mas.owasp.org/MASVS/)** categories and, for each control,
records:

- **MASVS category** — STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE,
  RESILIENCE, PRIVACY.
- **Module / component** — what implements it across the four planes (see
  [ARCHITECTURE.md](../ARCHITECTURE.md)).
- **MASTG verification** — how the control is tested using the
  **[OWASP MASTG](https://mas.owasp.org/MASTG/)** (test category + concrete
  procedure).

MASVS is the anchor standard precisely because it is open, testable, and
vendor-neutral (see [Standards Baseline](../PROPOSAL.md#standards-baseline)). The
[MASVS-RESILIENCE framing](../PROPOSAL.md#standards-baseline) is honored
throughout: resilience controls are defense-in-depth that raise attacker cost,
not primary controls — the authoritative decision is server-side.

## Table of Contents

- [How to Read This Mapping](#how-to-read-this-mapping)
- [MASVS-STORAGE](#masvs-storage)
- [MASVS-CRYPTO](#masvs-crypto)
- [MASVS-AUTH](#masvs-auth)
- [MASVS-NETWORK](#masvs-network)
- [MASVS-PLATFORM](#masvs-platform)
- [MASVS-CODE](#masvs-code)
- [MASVS-RESILIENCE](#masvs-resilience)
- [MASVS-PRIVACY](#masvs-privacy)
- [Coverage Summary](#coverage-summary)
- [Evidence Generation](#evidence-generation)

---

## How to Read This Mapping

Each category lists its MASVS control objectives (paraphrased) and the kseal
controls that satisfy them. The **MASTG test** column names the relevant MASTG
test area and the concrete check kseal's
[MASVS evidence report](../PROPOSAL.md#must-have-noops-features) runs per
release.

> Scope note: kseal is a *protection platform/SDK*, not the full end-user app.
> Several MASVS controls (e.g. business-logic authn) remain the tenant app's
> responsibility; this mapping marks those **Tenant** and documents how kseal
> *supports* them rather than claiming ownership.

---

## MASVS-STORAGE

Objective: sensitive data is stored securely and is not unintentionally exposed
via logs, caches, backups, or IPC.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| No sensitive data in logs | Privacy guard strips identifiers/PHI at source; no raw PII enters telemetry | Device plane: privacy guard (module 9); Rust core normalization | MASTG-STORAGE: inspect logcat/oslog + telemetry payloads during fuzzed sessions; assert no PII/secret tokens |
| No sensitive data in backups | SDK marks its keystore/keychain items non-exportable; nothing kseal-owned in auto-backup | Android `allowBackup`-safe storage; iOS Keychain `ThisDeviceOnly` | MASTG-STORAGE: trigger device backup, inspect for kseal artifacts |
| No secrets in app storage | No static secrets shipped; keys derived/hardware-bound at runtime | Secret protection (module 8); Keystore/StrongBox, Secure Enclave | MASTG-STORAGE + MASTG-RESILIENCE: static scan binary for embedded keys; runtime dump of app sandbox |
| Tenant data isolated at rest | Logical `tenant_id` namespacing + per-tenant keys server-side | Control plane: key management; data plane storage | Server test: attempt cross-`tenant_id` read; assert deny |
| Telemetry minimized at rest | Aggregates by default; raw events opt-in/paid; salted tenant-scoped hashes | Data plane: analytics writer, hot/cold tiering | MASTG-PRIVACY adjacent: inspect stored event schema; confirm no raw values |

---

## MASVS-CRYPTO

Objective: cryptography uses current algorithms, hardware-backed keys, and a
correct key lifecycle.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| Strong, current algorithms | Deterministic crypto message formats in Rust core (modern AEAD + signatures); no home-rolled crypto | Rust trust core: crypto message formats | MASTG-CRYPTO: review algorithm choices; assert no MD5/SHA-1/ECB/static IV |
| Hardware-backed keys | Request-proof keys in StrongBox / Secure Enclave; TPM/Keychain on desktop | Crypto binding layer (Android Keystore, iOS Secure Enclave) | MASTG-CRYPTO: confirm key is non-extractable, generated in hardware |
| Correct key lifecycle | Short-lived trust tokens; per-tenant key rotation; nonce freshness | Trust session service; control-plane key management (KMS/HSM) | Server test: token TTL enforced; rotated key invalidates old proofs |
| Deterministic, verifiable serialization | Byte-stable serialization so signing/verification match across platforms | Rust core: deterministic serialization | Unit/integration test: Android & iOS produce identical signed bytes for same input |
| No static key material | Keys derived or hardware-bound; nothing shippable to extract | Secret protection (module 8) | MASTG-CRYPTO + RESILIENCE: binary static analysis for embedded keys |

---

## MASVS-AUTH

Objective: authentication and authorization are correct, including step-up.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| Authenticate the *app instance* to the backend | Platform attestation + trust token bound to instance + build hash + risk + nonce + policy | Attestation verifier; trust session service | E2E test: tamper any binding field → token issuance/validation fails |
| Per-request authorization of sensitive actions | Signed request proof (hardware key + per-request nonce) | API request proof (module 7) | Server test: missing/forged proof → deny; replayed proof → deny |
| Step-up on elevated risk | Server policy emits `step-up` (MFA) instead of hard block | Risk engine; tenant policy | Policy-sim test: high-risk signal yields step-up decision |
| End-user authentication | **Tenant-owned**; kseal binds and strengthens the channel | Tenant API + kseal proof | Documented as tenant responsibility; kseal provides attested channel |
| Authorization isolation across tenants | `tenant_id` logical isolation + per-tenant keys | Control + data plane | Cross-tenant access test → deny |

---

## MASVS-NETWORK

Objective: secure transport, correct certificate handling, MITM resistance.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| TLS for all traffic | TLS everywhere; HTTP/2 origin, HTTP/3 terminated at edge | Transport layer; edge gateway | MASTG-NETWORK: intercept attempt; assert TLS, modern ciphers |
| Certificate pinning / MITM detection | Network-manipulation probe detects proxy/user-CA/pinning failure | Network manipulation (module 6); transport | MASTG-NETWORK: install user CA + proxy; assert signal raised, step-up |
| No cleartext fallback | Config + telemetry refuse cleartext; signed config rejects downgrade | Config service (CDN); transport | MASTG-NETWORK: attempt cleartext; assert refusal |
| Replay resistance on the wire | Per-request nonce; short-lived tokens | Request proof; trust session | Server test: capture+replay → deny |
| Config integrity in transit | Signed, cacheable config; device rejects unsigned/stale | Config service; device verification | Tamper CDN response → device rejects |

---

## MASVS-PLATFORM

Objective: safe use of platform features — IPC, WebView, permissions,
deep links.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| Minimal permissions | SDK requests no dangerous permissions; no location/contacts/ad-ID | Device plane SDK; privacy architecture | MASTG-PLATFORM: review manifest/Info.plist; assert minimal set |
| Safe IPC surface | SDK exposes no exported components/URL handlers that leak trust state | Android components; iOS URL schemes | MASTG-PLATFORM: enumerate exported components; assert none sensitive |
| No private/undocumented APIs (iOS) | Only public APIs (App Attest, DeviceCheck, Keychain, sysctl public surface) | iOS SDK; see [ios-app-review.md](ios-app-review.md) | Static symbol scan for private API usage; App Review safety review |
| Safe WebView usage | kseal ships no WebView; does not inject JS bridges | N/A (design constraint) | MASTG-PLATFORM: confirm no WebView in SDK |
| Deep-link / intent safety | No dynamic-code or intent-based control paths into the SDK | Device plane | MASTG-PLATFORM: fuzz intents/deep links into SDK |

---

## MASVS-CODE

Objective: dependency hygiene, secure defaults, code quality.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| Dependency hygiene | Minimal, audited dependency set; Rust core is the shared, audited-once logic | Rust core; SDK build | SCA scan (cargo-audit, dependency review) in CI |
| Secure defaults | Default policy `observe → step-up → block`; test mode never blocks | Risk engine; policy packs | Config review: defaults assert non-blocking until tuned |
| No dynamic code download | Config is data, not code; device rejects unsigned config | Config service; signed remote config | MASTG-CODE/RESILIENCE: confirm no runtime code load path |
| Memory safety in native | Rust core; CFI/MTE for native components where supported | Rust core; build-time hardening | Build verification: CFI/MTE flags present; fuzz native FFI boundary |
| Crash/ANR safety | SDK crash/ANR monitored as a release gate; fail-safe paths | SDK telemetry; CI gate | Soak test: assert near-zero crash/ANR contribution |
| Build provenance | Build proof records hashes/manifests; runtime verifies | Build proof (control plane); app integrity (module 1) | Verify unregistered build → server flags mismatch |

---

## MASVS-RESILIENCE

Objective: obfuscation, anti-debug, anti-tamper — explicitly framed as
**defense-in-depth** that raises attacker cost and buys detection time, with the
authoritative decision server-side.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| Anti-tamper / integrity | App-integrity + runtime-tamper probes; build-proof binding | Modules 1, 2; build proof | MASTG-RESILIENCE: patch binary/memory → assert signal + server block |
| Anti-debug | Debugger detection (`ptrace`/`TracerPid`, `sysctl` `P_TRACED`) | Module 3 | MASTG-RESILIENCE: attach lldb/gdb → assert detection |
| Anti-hooking | Detect Frida/Xposed/objection (maps, dyld images, ports, symbols) | Module 4 | MASTG-RESILIENCE: run Frida server → assert high-weight signal |
| Emulator/root/jailbreak detection | Environment-risk probe | Module 5 | MASTG-RESILIENCE: run on rooted/jailbroken/emulated device |
| Obfuscation + polymorphism | Per-build polymorphic obfuscation; string/symbol encryption | Build plane: Gradle/Xcode plugins | MASTG-RESILIENCE: diff two builds → assert structural divergence |
| Bypass decay | Server-side enforcement + per-build polymorphism so a crack does not transfer | Data plane risk engine + build plane | Demonstrate prior bypass fails against new build/policy |

> **Honest expectation-setting:** none of the above makes the client
> unbreakable. They raise cost and provide detection signals that the server
> fuses into the authoritative decision.

---

## MASVS-PRIVACY

Objective: data minimization, transparency, and user control.

| MASVS objective | kseal control | Module / component | MASTG verification |
|---|---|---|---|
| Data minimization | Compact events (enum types, packed risk bits, coarse confidence); default exclusions list | Privacy architecture; Rust core normalization | MASTG-PRIVACY: capture telemetry; assert only minimized fields |
| No cross-tenant correlation | Tenant-scoped rotating IDs; no device fingerprint | Privacy architecture | Test: same device on two tenants → no linkable ID |
| Transparency artifacts | iOS privacy manifest generator; Google Data Safety helper; machine-readable data contract | Compliance tooling | Generate artifacts; diff against actual collection |
| User/tenant control | Per-region retention; data-processing registry; raw events opt-in | Control plane: compliance | Config test: retention window enforced; registry populated |
| No prohibited collection | No GPS/contacts/ad-ID/installed-apps/keystroke/screen/clipboard | Privacy guard (module 9) | MASTG-PRIVACY: attempt to enable disallowed signal → dropped at source |

---

## Coverage Summary

Every MASVS category the platform targets has its kseal controls implemented
across the four planes. The **anchor** column names the plane(s) that carry the
bulk of each category's controls.

| MASVS category | Coverage | Anchor plane(s) |
|---|---|---|
| STORAGE | Full | Device (privacy guard) + Control (key management) |
| CRYPTO | Full | Device (Rust trust core) + Control (KMS/HSM) |
| AUTH | Full | Data (attestation + trust session) |
| NETWORK | Full | Device (transport) + Data (edge gateway) |
| PLATFORM | Full | Device (SDK surface) |
| CODE | Full | Build (hardening + build proof) + Device (Rust core) |
| RESILIENCE | Full | Device (RASP probes) + Build (polymorphism) |
| PRIVACY | Full | Device (privacy guard) + Control (compliance) |

CRYPTO/AUTH/NETWORK/PRIVACY rest on the trust-session backbone (the per-request
proof + attestation path); RESILIENCE rests on the runtime RASP probes plus
build-time polymorphism. The authoritative decision is server-side in every
case, so RESILIENCE controls remain defense-in-depth that raise attacker cost
rather than primary controls.

---

## Evidence Generation

Per [NoOps must-haves](../PROPOSAL.md#must-have-noops-features), a **MASVS
evidence report** is auto-generated per release. It is produced by composing:

1. **Static analysis** — binary scans (no embedded secrets, no private iOS APIs,
   modern crypto) and SCA dependency review run in CI.
2. **Build attestation** — the build proof (hashes/manifest, polymorphism
   parameters) recorded by the control plane.
3. **Runtime conformance** — automated MASTG procedures executed against
   reference builds on rooted/jailbroken/emulated and clean devices.
4. **Privacy contract diff** — the machine-readable SDK data contract checked
   against observed telemetry to confirm collection matches the declaration.

Each report cites the MASVS control ID, the kseal control, the MASTG procedure,
and a pass/fail with evidence, giving the tenant's security team and auditors an
external benchmark to verify against. Cross-reference:
[threat-model.md](threat-model.md) for the threats these controls mitigate, and
[ios-app-review.md](ios-app-review.md) / [android-policy-review.md](android-policy-review.md)
for store-specific constraints.
