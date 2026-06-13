# kseal — Desktop SDK (macOS + Windows)

The desktop SDKs bring the kseal device-plane to native **macOS** and **Windows**
applications. They are the desktop equivalent of the existing
[Android](../sdk/android) / [iOS](../sdk/ios) SDKs: they run **local integrity
checks** (RASP), fuse the results into the shared
[Rust trust core](../sdk/rust-core) over its C ABI, and drive a
[trust session](../ARCHITECTURE.md#device-plane) against the existing
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
| Notarization / timestamp | `SecAssessmentTicketLookup` presence | countersignature timestamp validity | **Real** |
| Hardened runtime / image flags | `kSecCodeInfoFlags` runtime bit | — | **Real** (macOS) |
| Binary structure integrity | code-signature validity (covers Mach-O) | `PeImage` PE header/section parser + section SHA-256 | **Real** |
| Injection / hooking | `DYLD_INSERT_LIBRARIES` + foreign dylibs | foreign loaded modules (outside app/OS dirs) | **Real** |
| Debugger attached (opt-in) | `sysctl(P_TRACED)` seam | `IsDebuggerPresent` / `Debugger.IsAttached` | **Real**, off by default |
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
  `SecCodeCopySigningInformation`, and `SecAssessmentTicketLookup`. No private
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
  storage; production should bind it to the platform key store (macOS
  Keychain/Secure Enclave, Windows TPM via CNG/`NCrypt`). That binding plugs in
  at the `ProofKeyProvider` / `IProofKeyProvider` seam.

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
```

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
| macOS | SwiftPM (Swift 6) on Linux | `swift build` + `swift test` against the real `libkseal_ffi.so` over the C ABI | **52 tests pass** |
| Windows | .NET 8 SDK on Linux | `dotnet build` (warnings-as-errors) + `dotnet test` against the real `libkseal_ffi.so` via P/Invoke | **72 tests pass** |

What is **real** in the test runs: the Rust trust core (FFI), risk
packing/scoring, request-proof generation/determinism, telemetry
batch/compress, PE parsing + section hashing, the Connect trust-flow
encode/decode, and all probe decision logic. What is **mocked**: the external OS
attestation/notary boundary (`CodeIntegrityAttestor` / `ICodeIntegrityAttestor`)
and the OS environment seam, so signature/PE/injection scenarios are driven
deterministically.

> The Windows `WinVerifyTrust` and macOS Security-framework calls are the
> production code paths; they are necessarily exercised against a real signed
> binary on the respective OS (Windows / macOS host) rather than on Linux CI.
> The Linux runs validate every platform-independent path against the real core
> and the OS seams via fakes.
