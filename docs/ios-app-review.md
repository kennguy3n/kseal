# kseal — iOS App Review Safety Analysis

A review confirming that the kseal iOS SDK is **App Store safe**: it uses
only public, documented APIs, performs no dynamic code download, does not
manipulate the dynamic linker, and ships the privacy-manifest material Apple
requires. It retires the **"iOS App Review rejection"** risk flagged
as *High* in the [Risk Assessment](../PROPOSAL.md#risk-assessment).

This complements the architecture's
[Attestation & API Protection](../ARCHITECTURE.md#attestation--api-protection)
and [On-Device Architecture](../ARCHITECTURE.md#on-device-architecture) sections,
and the [MASVS-PLATFORM](masvs-mapping.md#masvs-platform) mapping.

## Table of Contents

- [Why This Matters](#why-this-matters)
- [Public APIs Used](#public-apis-used)
- [No Private API Usage](#no-private-api-usage)
- [No Dynamic Code Download](#no-dynamic-code-download)
- [No DYLD / Dynamic-Linker Manipulation](#no-dyld--dynamic-linker-manipulation)
- [Jailbreak / Debug Detection — Safe Implementation](#jailbreak--debug-detection--safe-implementation)
- [Privacy Manifest Requirements](#privacy-manifest-requirements)
- [Required-Reason API Declarations](#required-reason-api-declarations)
- [App Attest & DeviceCheck Notes](#app-attest--devicecheck-notes)
- [Distribution & Build Plugin Safety](#distribution--build-plugin-safety)
- [App Review Pre-Submission Checklist](#app-review-pre-submission-checklist)

---

## Why This Matters

A protection SDK sits in a uniquely risky position with App Review because the
behaviors it needs (integrity checks, debugger/jailbreak detection, anti-tamper)
superficially resemble the behaviors Apple rejects (private API use, anti-Apple
tooling, dynamic code). The kseal design avoids rejection by construction:

- The **authoritative trust decision is server-side**, so the SDK never needs
  aggressive client-side enforcement that trips review heuristics.
- The SDK adds **no launch-time network call** and a **< 40 ms p95 startup
  overhead** ([Performance Budgets](../ARCHITECTURE.md#performance-budgets)), so
  it does not degrade the user experience reviewers evaluate.
- All detection uses **documented, public, observable signals** — not private
  symbols or undocumented entitlements.

---

## Public APIs Used

The iOS SDK relies exclusively on public frameworks. The table lists each API,
its purpose in kseal, and the framework.

| Capability | Public API / framework | kseal use |
|---|---|---|
| Hardware-backed attestation | `DCAppAttestService` (DeviceCheck framework) | Establish a hardware-backed attested key at first sensitive action |
| Per-device signal bits | `DCDevice` (DeviceCheck framework) | Low-frequency device bits verified server-side |
| Key storage / signing | `Security` framework: Keychain Services (`SecItem*`), `SecKey*` with `kSecAttrTokenIDSecureEnclave` | Generate non-extractable Secure Enclave key for request proofs |
| Cryptography | `CryptoKit` (and `Security`) | AEAD, signatures, hashing for proof/envelope formats |
| Debugger state | `sysctl` with `KERN_PROC`/`P_TRACED` (public BSD interface) | Read documented process flags; detect attached debugger |
| Anti-trace hardening | `ptrace(PT_DENY_ATTACH, …)` (public, documented) | Optional, opt-in; documented and used conservatively |
| Process / environment info | `NSProcessInfo`, `Bundle`, `FileManager` | Bundle integrity inputs, environment checks |
| Code-signature / bundle integrity | Reading the app's own embedded signature and Mach-O via documented file APIs | App-integrity module inputs (see below) |
| Networking | `URLSession` + `NWPathMonitor` (Network framework) | Batched telemetry, attestation challenge, proxy/path signals |
| TLS / pinning | `URLSession` delegate `urlSession(_:didReceive:)` + `SecTrust*` evaluation | Certificate validation and pinning, MITM detection |

All of the above are documented in Apple's developer reference and are routinely
accepted in App Review when used as described.

---

## No Private API Usage

kseal commits to **zero private/undocumented API usage**. This is verifiable and
will be enforced in CI as part of the
[MASVS evidence report](masvs-mapping.md#evidence-generation).

**How it is guaranteed and verified:**

- **Symbol allow-list scan.** A CI step dumps imported symbols
  (`nm -u`, `otool -L`, and dynamic-symbol inspection) for the SDK binary and
  compares against an allow-list of public framework symbols. Any symbol not
  resolvable to a public, documented API fails the build.
- **No `dlsym`/`NSClassFromString` to private classes.** The SDK does not look
  up private classes/selectors at runtime to evade static detection — itself a
  rejection trigger.
- **No private entitlements.** The SDK requires no special entitlements beyond
  the standard App Attest capability the host app already declares.

Specifically, kseal does **not** use any of the commonly-rejected private
surfaces: `MobileGestalt`/`gestalt` device identifiers, private `IOKit`
properties for fingerprinting, `_dyld`-private SPI, or undocumented
`ptrace`/`task_for_pid` privileged paths.

---

## No Dynamic Code Download

App Store Review Guideline **2.5.2** prohibits downloading or executing code that
changes the app's behavior. kseal is designed so that **config is data, never
code** (see [What to avoid](../ARCHITECTURE.md#what-kseal-deliberately-avoids)):

- **Signed remote config only.** Policy and module configuration are fetched as
  **signed data**, validated against an embedded public key, and *interpreted*
  by code already shipped in the binary. No bytecode, scripts, or executables are
  downloaded.
- **Device rejects unsigned/stale config.** A tampered or downgraded config is
  refused, so the config channel cannot be repurposed to inject behavior.
- **No JS bridge / no WebView execution path.** The SDK ships no `WKWebView`
  and evaluates no remote JavaScript.
- **Policies are declarative.** A policy expresses *which signals matter and
  what decision applies*; the evaluation logic is fixed in the shipped Rust core
  and the server, not delivered at runtime.

This keeps kseal firmly inside 2.5.2 while still allowing rapid policy updates —
the updates change *data*, not the program.

---

## No DYLD / Dynamic-Linker Manipulation

kseal does **not** manipulate the dynamic linker in any way that App Review
penalizes:

- **No `DYLD_INSERT_LIBRARIES` use.** The SDK neither sets nor relies on dyld
  insertion. On *desktop* (macOS) it *detects*
  `DYLD_INSERT_LIBRARIES` injection as a signal
  ([macOS modules](../ARCHITECTURE.md#macos-modules)) — detection is reading the
  environment, not performing injection.
- **No runtime dylib loading from non-standard paths.** All linked frameworks
  are embedded in the app bundle and signed; nothing is `dlopen`-ed from a
  downloaded or writable location.
- **No method swizzling of system frameworks** to alter Apple behavior. The SDK
  observes; it does not patch the runtime.

The iOS integrity module verifies **Mach-O section hashes and load commands**
against the build manifest by *reading* the app's own image — a read-only
integrity check, not linker manipulation.

---

## Jailbreak / Debug Detection — Safe Implementation

Detection is permitted; the rejection risk comes from *how* it is implemented.
kseal's rules:

| Practice | kseal approach |
|---|---|
| Use only public, observable signals | `sysctl`/`P_TRACED`, file-existence checks for known jailbreak artifacts, sandbox-escape probes via documented APIs |
| Never use private anti-debug SPI | No `task_for_pid` on other processes, no private kernel interfaces |
| Detection is a *signal*, not a hard client block | Result feeds the server; default posture is `observe → step-up`, avoiding reviewer-visible crashes/lockouts |
| No degraded UX during review | On a clean (non-jailbroken, non-debugged) device — the reviewer's environment — the SDK is silent and adds < 40 ms startup |
| Conservative `PT_DENY_ATTACH` | Opt-in per tenant; documented; never used in a way that breaks legitimate crash reporting |

Because the reviewer's device is normally clean, detection logic does not trigger
during review, and even if it did, the SDK never hard-blocks or crashes — it
reports a signal.

---

## Privacy Manifest Requirements

Apple requires a **privacy manifest** (`PrivacyInfo.xcprivacy`) for SDKs and
mandates manifests + signatures for certain SDKs. kseal ships a privacy manifest
and auto-generates the host-app material via the
[iOS privacy manifest generator](../ARCHITECTURE.md#store-compliance).

The kseal SDK's `PrivacyInfo.xcprivacy` declares:

- **`NSPrivacyTracking`**: `false` — kseal performs **no tracking** as Apple
  defines it (no linking with third-party data, no cross-app/identity
  correlation). This is consistent with the
  [Privacy Architecture](../ARCHITECTURE.md#privacy-architecture).
- **`NSPrivacyTrackingDomains`**: empty — no tracking domains.
- **`NSPrivacyCollectedDataTypes`**: minimized. kseal collects **device-risk
  signals** (not in Apple's "data types" sense of PII); any reportable type is
  declared as collected for **App Functionality / Fraud Prevention, Security**,
  **not linked to identity**, and **not used for tracking**.
- **`NSPrivacyAccessedAPITypes`**: declares the required-reason APIs (below).

**Signed SDK.** kseal distributes the iOS SDK as a **signed XCFramework** so the
host app inherits a valid privacy manifest + signature, satisfying Apple's
third-party SDK requirements.

---

## Required-Reason API Declarations

Apple's "required reason API" rules require declaring an approved reason for
certain APIs. The SDK declares only what it actually uses:

| API category | Used? | Declared reason code | Justification |
|---|---|---|---|
| File timestamp APIs | Possibly (bundle integrity) | `C617.1` / `3B52.1` (as applicable) | Read timestamps of files **inside the app's own container** for integrity |
| System boot time (`systemUptime`) | Possibly (anti-replay/freshness) | `35F9.1` | Measure elapsed time for nonce/freshness, not for fingerprinting |
| Disk space APIs | No | — | kseal does not query free space |
| Active keyboard APIs | No | — | Not used |
| User defaults | If used for SDK state | `CA92.1` | Access **only the app's own** defaults for SDK state |

The generator validates that every accessed required-reason API has a declared,
truthful reason; an undeclared access fails the build. No API is used for device
fingerprinting, which is the disallowed reason class.

---

## App Attest & DeviceCheck Notes

- **App Attest** (`DCAppAttestService`) establishes a hardware-backed key
  attested by Apple at first use; kseal verifies the attestation **server-side**
  in the [attestation verifier](../ARCHITECTURE.md#ios--app-attest--devicecheck).
  The key lives in the Secure Enclave and is non-extractable.
- **DeviceCheck** (`DCDevice`) provides two per-device bits and a server-verified
  token for lower-frequency signals.
- Both are **public, Apple-blessed** anti-fraud mechanisms — using them is a
  positive signal in review, not a risk. kseal calls them **only on sensitive
  actions** and caches the resulting trust session to respect rate limits and the
  startup budget.
- **Availability handling:** App Attest is unavailable on Simulator and some
  configurations; the SDK degrades gracefully (falling back to kseal's own
  signals and server risk fusion) rather than crashing — important both for
  resilience and for not disrupting App Review on simulator-based testing.

---

## Distribution & Build Plugin Safety

The [build-time hardening](../ARCHITECTURE.md#ios) for iOS is delivered as an
**XCFramework + Swift Package + Xcode build plugin** that runs **locally in the
tenant's CI**:

- The build plugin performs **section hashing and metadata stripping** on the
  tenant's own build output — standard, App-Review-safe transformations that
  preserve a valid code signature.
- kseal explicitly **avoids heavy VM/virtualization obfuscation**
  ([What to avoid](../ARCHITECTURE.md#what-kseal-deliberately-avoids)) because of its App Store
  risk and marginal benefit given server-side enforcement.
- Crash symbolication is preserved (mapping material retained), so the hardened
  app still produces usable crash reports — avoiding the "broken app" rejection
  path.

---

## App Review Pre-Submission Checklist

A release gate, runnable in CI, that must pass before any kseal-protected iOS
build is submitted:

- [ ] Private-API symbol scan passes (allow-list only).
- [ ] No `DYLD_INSERT_LIBRARIES` use; no `dlopen` from writable/downloaded paths.
- [ ] No dynamic code/script download; config channel is signed-data-only.
- [ ] `PrivacyInfo.xcprivacy` present; `NSPrivacyTracking = false`; data types
      declared for security/fraud, not linked to identity, not for tracking.
- [ ] All required-reason APIs declared with truthful reason codes.
- [ ] XCFramework signed; SDK privacy manifest present and valid.
- [ ] On a clean device: startup overhead < 40 ms p95, no crashes/ANRs, SDK
      silent (no hard blocks).
- [ ] App Attest/DeviceCheck used on sensitive actions only; graceful fallback on
      unsupported environments (incl. Simulator).
- [ ] No prohibited data collection (location, contacts, ad-ID, etc. per
      [default exclusions](../ARCHITECTURE.md#default-exclusions)).

Passing this checklist closes the
[iOS App Review rejection risk](../PROPOSAL.md#risk-assessment) and supplies the
iOS half of the [MASVS-PLATFORM](masvs-mapping.md#masvs-platform) evidence.
