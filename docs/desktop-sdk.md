# kseal — Desktop SDK (macOS + Windows)

The desktop SDKs bring the kseal device-plane to native **macOS** and **Windows**
applications. They are the desktop equivalent of the existing
[Android](../sdk/android) / [iOS](../sdk/ios) SDKs: they run **local integrity
checks** (RASP), fuse the results into the shared
[Rust trust core](../sdk/rust-core) over its C ABI, and drive a
[trust session](../ARCHITECTURE.md#trust-session-flow) against the existing
`TrustService` RPCs. As with mobile, the SDK never makes the trust decision —
it raises attacker cost and feeds signals; the **server decides**
([MASVS-RESILIENCE framing](../PROPOSAL.md#standards-baseline)).

- macOS: a SwiftPM package, `KsealDesktop` — [`sdk/desktop/macos`](../sdk/desktop/macos).
- Windows: a .NET (C#) library, `Kseal.Desktop` — [`sdk/desktop/windows`](../sdk/desktop/windows).

## Table of Contents

- [Architecture & FFI Boundary](#architecture--ffi-boundary)
- [What is checked (real) vs. mocked](#what-is-checked-real-vs-mocked)
- [Public-API-only / store-safety rationale](#public-api-only--store-safety-rationale)
- [Mock boundaries](#mock-boundaries)
- [Threat model: desktop caution](#threat-model-desktop-caution)
- [Enterprise compatibility controls](#enterprise-compatibility-controls)
- [Hardware-bound request proofs](#hardware-bound-request-proofs)
- [Secure software updates](#secure-software-updates)
- [Performance & footprint budget](#performance--footprint-budget)
- [Privacy & multi-tenant isolation](#privacy--multi-tenant-isolation)
- [Integration guide — macOS](#integration-guide--macos)
- [Integration guide — Windows](#integration-guide--windows)
- [Building & testing](#building--testing)
- [Validation summary](#validation-summary)

---

## Architecture & FFI Boundary

Both SDKs link the **already-built** `kseal-ffi` shared library
(`libkseal_ffi.dylib` / `kseal_ffi.dll` / `libkseal_ffi.so`) and consume the
generated C header [`kseal.h`](../sdk/rust-core/kseal-ffi/include/kseal.h) exactly
like the mobile SDKs consume the FFI. **The Rust crate is not modified by the
desktop SDKs.**

```
 ┌─────────────────────────── desktop app process ───────────────────────────┐
 │  native probes (per-OS, public APIs)        shared trust logic (Rust core)  │
 │  ┌──────────────────────────────┐           ┌──────────────────────────┐   │
 │  │ macOS: SecCode / SecStaticCode│           │ kseal_evaluate_risk      │   │
 │  │ Windows: WinVerifyTrust / PE  │  signals  │ kseal_compute_risk_level │   │
 │  │  → RiskSignal bitset (u64) ───┼──────────▶│ kseal_create_event       │   │
 │  └──────────────────────────────┘   C ABI   │ kseal_generate_request…  │   │
 │                                              └────────────┬─────────────┘   │
 └───────────────────────────────────────────────────────────┼───────────────┘
                                                              │ trust session (off hot path)
                                                              ▼
                                        TrustService: GetNonce → VerifyAttestation
                                                       → ValidateRequestProof
```

The on-device probes only **produce a `u64` risk bitset**. The bit layout is
shared verbatim across every SDK and the core's `RiskBitset`
(`sdk/rust-core/kseal-core/src/risk.rs`); see `RiskSignal.swift` /
`RiskSignal.cs`. Scoring, trust-level thresholds, telemetry batching, and request
proofs are all delegated to the core over the FFI — there is no second
implementation of trust logic on the desktop.

### Why C#/.NET for Windows

C#/.NET is the idiomatic surface for Windows desktop apps (WPF / WinForms /
WinUI / .NET console). The SDK binds the same C ABI via **P/Invoke**, mirroring
how the mobile SDKs bind the FFI; `WinVerifyTrust` and the certificate APIs are
first-class. The library targets plain `net8.0` (not `net8.0-windows`) so the
platform-independent integrity logic builds and unit-tests on any host, with the
Win32-only calls guarded by `OperatingSystem.IsWindows()` /
`[SupportedOSPlatform("windows")]`. (A Rust+win32 client was the alternative; it
would have meant a second-class API for the overwhelmingly-managed Windows app
ecosystem.)

## What is checked (real) vs. mocked

| Check | macOS | Windows | Real or mocked |
|---|---|---|---|
| Code signature present & valid | `SecCodeCopySelf` → `SecStaticCodeCheckValidity` | `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`) | **Real** (production impl) |
| Signing identity / team / publisher | `kSecCodeInfoTeamIdentifier`, `…Identifier` | `X509Certificate.CreateFromSignedFile` subject + thumbprint | **Real** |
| Notarization / timestamp | `SecAssessmentCreate` Gatekeeper execute assessment | Authenticode PKCS#7 countersignature (`SignedCms`) | **Real** |
| Hardened runtime / image flags | `kSecCodeInfoFlags` runtime bit | — | **Real** (macOS) |
| Binary structure integrity | code-signature validity (covers Mach-O) | `PeImage` PE header/section parser + section SHA-256 | **Real** |
| Injection / hooking | `DYLD_INSERT_LIBRARIES` + foreign dylibs | foreign loaded modules (outside app/OS dirs) | **Real** |
| Debugger attached (opt-in) | `sysctl(P_TRACED)` seam | `IsDebuggerPresent` / `Debugger.IsAttached` | **Real**, off by default |
| Hardware-bound proof key | Keychain / Secure Enclave (`SecKey`, P-256) | TPM via CNG Platform Crypto Provider (`RSACng`) | **Real** (software fallback) |
| Secure-update signature | Sparkle EdDSA appcast (Ed25519 over archive) | Ed25519-signed manifest + optional Authenticode payload check | **Real** verification, mocked feed |
| Enterprise policy source | managed preferences (`CFPreferences`, `io.kseal.desktop`) | GPO/MDM registry (`HKLM\…\Policies\Kseal\Desktop`) / JSON | **Real** |
| Risk scoring / trust level | Rust core via FFI | Rust core via FFI | **Real** core |
| Trust session RPCs | `TrustService` over Connect | `TrustService` over Connect | **Real** contract |
| External attestation token source | `CodeIntegrityAttestor` interface | `ICodeIntegrityAttestor` interface | **Mocked boundary** (real default + test fake) |

Everything internal is real and exercised by tests against the **real Rust
core** over the FFI. Only the external OS-attestation/notary call surface is
behind an interface (real default impl + test fake), per the engineering rules.

## Public-API-only / store-safety rationale

Both SDKs use **only public, documented OS APIs**, so an app embedding kseal
stays acceptable for the **Mac App Store / Gatekeeper / notarization** and for
Windows code-signing/SmartScreen, and survives OS updates:

- **macOS** uses the public **Security framework**: `SecCodeCopySelf`,
  `SecCodeCopyStaticCode`, `SecStaticCodeCheckValidity`,
  `SecCodeCopySigningInformation`, and `SecAssessmentCreate`. No private
  SPI, no `task_for_pid` against other processes, no kernel pokes, no
  `amfid`/`csops` spelunking. The SDK only inspects **its own** running code, so
  it needs no extra entitlements and is hardened-runtime/sandbox compatible.
- **Windows** uses **WinVerifyTrust** (the same API Explorer/SmartScreen use)
  and the managed `X509Certificate` APIs, plus pure-managed PE parsing of the
  app's own image. No undocumented syscalls, no `ntdll` private routines, no
  self-modifying anti-debug tricks that AV would flag.

Anti-debugging is **opt-in** (see below) precisely because aggressive anti-debug
is the kind of behavior that draws AV heuristics and breaks legitimate
admin/debug workflows on desktop.

## Mock boundaries

The only mocked surface is the **external OS attestation / notary** call — the
third-party service boundary the engineering rules say to mock. It is expressed
as an interface with a **real default implementation** and a **test fake**:

- macOS: `CodeIntegrityAttestor` (default `LocalCodeIntegrityAttestor`) and the
  `DesktopEnvironment` seam (default `MacDesktopEnvironment`).
- Windows: `ICodeIntegrityAttestor` (default `LocalCodeIntegrityAttestor`) and
  the `IWindowsEnvironment` seam (default `WindowsEnvironment`).

Three further external boundaries follow the same
real-default-plus-fake pattern:

- **Secure-update feed** — `AppcastFeed` (macOS) / `IUpdateFeed` (Windows): the
  third-party update channel. The signature/length/notarization/Authenticode
  verification on top of it is **real**; only the feed transport is mocked
  (`InMemoryAppcastFeed` / `InMemoryUpdateFeed`).
- **Secure element** — `HardwareKeyStore` (macOS) / `IHardwareKeyStore`
  (Windows): the Keychain/TPM seam used to seal the request-proof key. A test
  fake exercises the seal/unseal logic without real hardware.
- **Notary / payload verifier** — `UpdateNotaryVerifier` (macOS) /
  `IUpdatePackageVerifier` (Windows): the Gatekeeper/Authenticode payload check,
  consulted only when policy requires it.

The default attestor derives a compact, **non-PII** local attestation from the
verified code-signing identity (team/publisher + cdhash/thumbprint). There is no
first-party desktop remote-attestation service comparable to Play Integrity /
App Attest; an integrator fronting a cloud KMS/HSM or TPM-quote service plugs a
real implementation in at this exact seam. Tests substitute a fake environment
to drive *valid / tampered / unsigned / wrong-identity / stripped-signature*
cases deterministically without touching the host OS.

`IWindowsEnvironment` / `DesktopEnvironment` are also the seams that make the
integrity logic unit-testable on Linux CI: the production impl reads the real
process; the fake supplies controlled signatures and PE images.

## Threat model: desktop caution

Desktop differs from mobile: debugging, DLL/dylib side-loading for plugins, and
developer tooling are **legitimate and common**. Treating every debugger or
foreign module as hostile would generate false positives. Therefore:

- The **debugger probe is disabled by default** and must be enabled explicitly
  (`EnabledProbes` / probe selection). Hosts that ship locked-down kiosks can
  opt in.
- Integrity findings are **signals, not verdicts** — they are scored by the core
  and adjudicated server-side, where per-tenant policy decides tolerance.
- Security-relevant ambiguity **fails closed**: an app that cannot read/parse its
  own signature or PE image raises tamper/app-integrity rather than passing.

## Enterprise compatibility controls

Desktop deployments span locked-down kiosks, managed developer fleets, and
regulated tiers. The SDK reads an **MDM-friendly, auditable policy** so an
enterprise can relax or tighten posture without a code change. **Every default
is strict**: an unconfigured policy (`EnterprisePolicy.strict`) relaxes nothing
and is byte-for-byte the pre-existing behavior, so this never changes the default
behavior on `main`. The effective policy is surfaced
(`KsealDesktop.enterprisePolicy` / `KsealDesktopClient.EnterprisePolicy`) so a
deployment can audit exactly what was relaxed.

| Control | Effect | Strict default |
|---|---|---|
| `permitDebugger` | Drops the debugger probe even if explicitly enabled — for managed dev machines where debugging is legitimate | `false` |
| `injectionAllowlist` | Module paths (exact match or directory prefix ending in a path separator) that are sanctioned plugins/agents and do **not** raise the injection signal | `[]` |
| `telemetryVerbosity` | `minimal` drops clean (no-signal) events to cut volume; `standard` records everything; `verbose` reserved for extra diagnostics | `standard` |
| `requireHardwareBackedProofKey` | When the proof key is **not** hardware-backed, raise `secureHwMissing` so the server can fail closed for a regulated tier | `false` |

**Where it is read (managed configuration):**

- **macOS** — managed preferences for domain `io.kseal.desktop` (a configuration
  profile pushed by MDM), via the public `CFPreferences` API. Keys:
  `PermitDebugger` (bool), `InjectionAllowlist` (array of string),
  `TelemetryVerbosity` (string), `RequireHardwareBackedProofKey` (bool). A JSON
  drop file (`FileEnterprisePolicyProvider`) is the fallback/test seam.
- **Windows** — GPO/MDM-delivered machine policy under
  `HKLM\SOFTWARE\Policies\Kseal\Desktop`: `PermitDebugger` /
  `RequireHardwareBackedProofKey` (REG_DWORD, non-zero = true),
  `InjectionAllowlist` (REG_MULTI_SZ), `TelemetryVerbosity` (REG_SZ). A JSON drop
  file is the cross-platform fallback/test seam.

Unset keys keep the strict default, so a partial managed config only relaxes the
keys it explicitly sets. A missing or malformed config yields the strict
baseline (fail safe). Hosts that manage policy themselves can inject one directly
via `KsealDesktopOptions.enterprisePolicy`.

## Hardware-bound request proofs

The per-request proof is `HMAC(proofKey, …)` computed by the shared core; the
**byte layout is identical across every SDK** (mobile and desktop) and is
unchanged by this module — only *how the `proofKey` is protected at rest* gains a
hardware binding.

- **macOS** — `HardwareKeyStore` seals the key with a Keychain / Secure-Enclave
  P-256 key (ECIES) before it is persisted.
- **Windows** — `TpmHardwareKeyStore` seals it with a non-exportable RSA key in
  the **Microsoft Platform Crypto Provider** (TPM); unsealing decrypts inside the
  TPM, so the on-disk blob is useless on another machine.

Both wrap a **clean software fallback** (`SoftwareKeyStore` / passthrough) used
when no secure element is present (CI, virtualized hosts). Continuity is
preserved: a legacy *raw* key already on disk is adopted and re-sealed in place,
and if hardware sealing fails the SDK persists the raw key (software-equivalent)
rather than bricking the host. When `requireHardwareBackedProofKey` is set and
the binding is unavailable, the SDK raises `secureHwMissing` (fail closed). The
binding plugs in at the `ProofKeyProvider` / `IProofKeyProvider` seam
(`HardwareBoundProofKeyProvider`).

## Secure software updates

A self-updating desktop app is a high-value supply-chain target: an unverified
update channel is remote code execution. The SDK verifies an update channel
**before anything is applied** and **fails closed** on any verification failure.
See [desktop-secure-update.md](desktop-secure-update.md) for the full design,
threat model, and feed formats.

- **macOS** — `SecureUpdateChannel` parses a **Sparkle-style signed appcast**
  (`AppcastParser`, namespace-aware `XMLParser`), selects the newest applicable
  item, length-checks the archive, and verifies its **Ed25519 (EdDSA)** signature
  against the channel key using the **same Rust-core primitive** as config
  verification. Optional notarization is checked via the `UpdateNotaryVerifier`
  seam.
- **Windows** — `SecureUpdateChannel` parses an **Ed25519-signed JSON manifest**,
  applies the same length + signature verification, and (when
  `RequireAuthenticode` is set) verifies the **Authenticode** signature of the
  downloaded payload via the `IUpdatePackageVerifier` seam.

The external **feed** is mocked behind `AppcastFeed` / `IUpdateFeed`; all
verification logic is real and unit-tested against the real Ed25519 verifier with
fixed test vectors. Cryptographic failures never return an update; a
network/parse failure is treated as "no update available".

## Performance & footprint budget

- **No launch-time network.** Initialization only loads a cached signed config
  (if present) and brings up the core. The trust session is established **only**
  when the host calls `establishTrustSession()` — off the hot path, exactly like
  mobile.
- Probes are cheap, allocation-light, side-effect-free, and **never block on
  network**. The macOS code-signing inspection and the Windows
  `WinVerifyTrust` result are computed once and cached so repeated probe runs are
  effectively free. Aggregate startup overhead stays within the **< 40 ms** SDK
  budget.
- The SDK adds only thin native glue over the shared core; it carries no heavy
  dependencies (no embedded protobuf runtime — a focused wire reader decodes the
  one response message used).

## Privacy & multi-tenant isolation

- **No PII in logs or telemetry.** Telemetry events carry only the packed risk
  bitset and coarse metadata; the core's privacy guard masks event types / risk
  bits / geography before export.
- The install identity is a random local id; only a **tenant-scoped HMAC** of it
  (`HMAC-SHA256(installId, "tenant\0app")`) ever leaves the device, so the same
  install is uncorrelatable across tenants. HMAC (not `SHA256(id || ctx)`) avoids
  length-extension and matches the other SDKs' construction.
- Tenant isolation is **logical** via `tenant_id` on every RPC — no per-tenant
  schema, consistent with the ~5000-SME model in
  [ARCHITECTURE.md](../ARCHITECTURE.md).
- The request-proof HMAC key is generated locally and persisted in app-private
  storage, **sealed by the platform key store** where available (macOS
  Keychain/Secure Enclave, Windows TPM via CNG), with a software fallback — see
  [Hardware-bound request proofs](#hardware-bound-request-proofs). The on-disk
  bytes for the software fallback are byte-identical to the prior default, so
  existing installs keep their key and their server-side trust continuity.

## Integration guide — macOS

Add the package (path or Git URL) and depend on the `KsealDesktop` product:

```swift
// Package.swift
dependencies: [
    .package(path: "../kseal/sdk/desktop/macos"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "KsealDesktop", package: "macos"),
    ]),
]
```

```swift
import KsealDesktop

// 1. Initialize once at launch (no network performed).
let kseal = try KsealDesktop.initialize(
    tenantId: "acme",
    appId: "com.acme.app",
    options: .init(
        configPublicKey: tenantConfigPublicKey,   // Ed25519, 32 bytes
        buildHash: "<content-hash-of-this-build>",
        integrityPolicy: .init(expectedTeamIdentifier: "ABCDE12345")
    )
)

// 2. Evaluate local integrity on demand (cheap, offline).
let assessment = try kseal.evaluateRisk()
if !assessment.isClean { /* react to assessment.trustLevel */ }

// 3. Establish a trust session off the hot path (the SDK's only network call).
let client = ConnectTrustSessionClient(
    config: .init(baseURL: trustBaseURL, tenantId: "acme", appId: "com.acme.app"))
let session = try kseal.establishTrustSession(using: client)

// 4. Bind sensitive requests to the trust token.
let proof = try kseal.getRequestProof(requestHash: sha256(ofRequest))
// attach proof.proofBytes to the outbound request; server validates it.

// 5. Verify a signed update channel before applying (fails closed).
let channel = SecureUpdateChannel(
    policy: .init(publicKey: appcastPublicKey, currentVersion: .init("1.4.0"),
                  requireNotarization: true),
    feed: myAppcastFeed)              // your transport behind the AppcastFeed seam
switch try channel.checkForUpdate() {
case .upToDate: break
case .updateAvailable(let verified): apply(verified.archive)   // signature + notarization already verified
}
```

The effective enterprise policy is read from managed preferences automatically;
to inject one explicitly: `options = .init(..., enterprisePolicy: .init(permitDebugger: true))`.

## Integration guide — Windows

Reference the project (or its NuGet package) from your app:

```xml
<ItemGroup>
  <ProjectReference Include="..\kseal\sdk\desktop\windows\src\Kseal.Desktop\Kseal.Desktop.csproj" />
</ItemGroup>
```

Ship `kseal_ffi.dll` alongside the app (or set `KSEAL_FFI_LIBRARY` to an absolute
path). Then:

```csharp
using Kseal.Desktop;

// 1. Initialize once at launch (no network performed).
var kseal = KsealDesktopClient.Initialize(
    tenantId: "acme",
    appId: "com.acme.app",
    options: new KsealDesktopOptions
    {
        ConfigPublicKey = tenantConfigPublicKey,     // Ed25519, 32 bytes
        BuildHash = "<content-hash-of-this-build>",
        IntegrityPolicy = new WindowsIntegrityPolicy
        {
            ExpectedPublisher = "CN=Acme Corp, O=Acme Corp, C=US",
            ExpectedCertificateThumbprint = "9F8E…",
        },
    });

// 2. Evaluate local integrity on demand (cheap, offline).
RiskAssessment assessment = kseal.EvaluateRisk();
if (!assessment.IsClean) { /* react to assessment.TrustLevel */ }

// 3. Establish a trust session off the hot path.
using var transport = new HttpClientTransport();
var client = new ConnectTrustSessionClient(
    new TrustSessionConfig(trustBaseUrl, "acme", "com.acme.app"), transport);
TrustSession session = kseal.EstablishTrustSession(client);

// 4. Authorize sensitive requests (ALLOW / STEP_UP / DENY from the server).
RequestProofDecision decision = kseal.AuthorizeRequest(sha256OfRequest, client);
```

To enable the opt-in debugger probe for a locked-down deployment:

```csharp
options = options with { EnabledProbes = new HashSet<string>
    { "windows.authenticode", "windows.peIntegrity", "windows.dllInjection", "windows.debugger" } };
```

To verify a signed update channel before applying it (fails closed):

```csharp
var channel = new SecureUpdateChannel(
    new UpdateChannelPolicy
    {
        PublicKey = updatePublicKey,                 // Ed25519, 32 bytes
        CurrentVersion = new UpdateVersion("1.4.0"),
        RequireAuthenticode = true,                  // also verify the payload's Authenticode
    },
    myUpdateFeed);                                   // your transport behind the IUpdateFeed seam
switch (channel.CheckForUpdate())
{
    case SecureUpdateResult.UpToDate: break;
    case SecureUpdateResult.UpdateAvailable a: Apply(a.Update.Archive); break; // already fully verified
}
```

The effective enterprise policy is read from GPO/MDM registry automatically; to
inject one explicitly: `options with { EnterprisePolicy = new EnterprisePolicy { PermitDebugger = true } }`.

## Building & testing

### macOS (SwiftPM)

```bash
cd sdk/desktop/macos
swift build
swift test
```

`Package.swift` links the host build of the shared library and sets an rpath so
tests resolve it at runtime. Build the core first if needed:
`cargo build --manifest-path ../../rust-core/Cargo.toml -p kseal-ffi`.

### Windows (.NET)

```bash
cd sdk/desktop/windows
# Build the host shared lib and export its path for the P/Invoke resolver:
eval "$(bash scripts/build-rust-host.sh | tail -1)"
dotnet build src/Kseal.Desktop/Kseal.Desktop.csproj
dotnet test  tests/Kseal.Desktop.Tests/Kseal.Desktop.Tests.csproj
```

`NativeMethods` registers a `DllImportResolver` that honors `KSEAL_FFI_LIBRARY`
(absolute path to the shared lib), so tests run against the **real core** on any
host; in production the loader finds `kseal_ffi.dll` next to the app. The Win32
integrity calls only execute on Windows; on other hosts the platform-independent
logic is unit-tested via the `IWindowsEnvironment` fake.

## Validation summary

| SDK | Toolchain | How validated | Result |
|---|---|---|---|
| macOS | SwiftPM (Swift 5.10) on Linux | `swift build` + `swift test` against the real `libkseal_ffi.so` over the C ABI | **91 tests pass** |
| Windows | .NET 8 SDK on Linux | `dotnet build` (warnings-as-errors) + `dotnet test` against the real `libkseal_ffi.so` via P/Invoke | **119 tests pass** |

What is **real** in the test runs: the Rust trust core (FFI), risk
packing/scoring, request-proof generation/determinism, telemetry
batch/compress, PE parsing + section hashing, the Connect trust-flow
encode/decode, all probe decision logic, the **secure-update signature/length
verification** (real Ed25519 over the FFI with fixed test vectors), the
**proof-key seal/unseal** logic (via a fake secure element), and the
**enterprise-policy** parsing/wiring. What is **mocked**: the external OS
attestation/notary boundary (`CodeIntegrityAttestor` / `ICodeIntegrityAttestor`),
the OS environment seam, the secure-update *feed*, and the secure element /
notary, so all scenarios are driven deterministically.

> The Windows `WinVerifyTrust` and macOS Security-framework calls are the
> production code paths; they are necessarily exercised against a real signed
> binary on the respective OS (Windows / macOS host) rather than on Linux CI.
> The Linux runs validate every platform-independent path against the real core
> and the OS seams via fakes.
