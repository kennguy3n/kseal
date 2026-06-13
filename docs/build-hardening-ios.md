# kseal — iOS Build-Time Hardening

How the kseal iOS build plane hardens an app at build time and registers a
**build proof** the runtime and control plane can later verify. It documents the
[`plugins/xcode`](../plugins/xcode) toolkit: the XCFramework packaging pipeline,
the SwiftPM/Xcode **build-tool plugin**, and the **canonical build-proof
manifest** shared with the Android/Gradle plane (WS-B).

This is the iOS counterpart to the Android entries in
[ARCHITECTURE.md#android](../ARCHITECTURE.md#android) and the
[Build-Time Hardening](feature-parity-matrix.md#build-time-hardening) matrix, and
it is bound by the strict public-APIs-only constraint in
[ios-app-review.md](ios-app-review.md).

## Table of Contents

- [Goals](#goals)
- [Components](#components)
- [The build-proof manifest (canonical schema)](#the-build-proof-manifest-canonical-schema)
- [Per-build polymorphism seed](#per-build-polymorphism-seed)
- [String hardening](#string-hardening)
- [Symbol & metadata stripping](#symbol--metadata-stripping)
- [Registering the build proof](#registering-the-build-proof)
- [Using the plugin](#using-the-plugin)
- [XCFramework pipeline](#xcframework-pipeline)
- [App Store safety](#app-store-safety)
- [Threat model & honest limits](#threat-model--honest-limits)
- [Testing](#testing)

---

## Goals

- Harden an iOS app **in the tenant's own CI** — no per-build cloud compute
  ([ARCHITECTURE.md#build-plane](../ARCHITECTURE.md)).
- Produce a **build proof** (hashes, applied transforms, per-build polymorphism
  digest, tool versions, SDK version) and register it via
  [`RegistryService.CreateBuild`](../proto/kseal/v1/registry_service.proto) so a
  runtime **build-proof check** can reject unknown/modified builds
  (threat [B5](threat-model.md)).
- Stay **App Store safe by construction**: public toolchain only, no private
  APIs, no entitlement abuse, no dynamic code.
- Mirror the Android/Gradle plane so one manifest schema validates both
  platforms.

## Components

The [`plugins/xcode`](../plugins/xcode) SwiftPM package (`KsealHarden`):

| Product | Kind | Responsibility |
|---|---|---|
| `KsealHardenCore` | library | Portable, dependency-free hardening logic: polymorphism seed, string obfuscation, symbol stripping, manifest, registry client. Fully unit-testable on any Swift toolchain. |
| `kseal-harden` | executable | The build-tool the plugins invoke (`generate`, `register`, `harden-binary`, `version`). |
| `KsealHardenPlugin` | build-tool plugin | Runs at build time: string hardening + build-proof emission. **No network** (build-tool plugins are sandboxed). |
| `KsealRegisterPlugin` | command plugin | Registers the emitted proof with the control plane (network-permitted) with an offline fallback. |

`KsealHardenCore` vendors a small, test-vectored SHA-256 so the toolkit has
**zero external dependencies** and resolves/builds fully offline inside the
plugin sandbox.

## The build-proof manifest (canonical schema)

One JSON schema is shared by **every** build plane (iOS here, Android via WS-B),
so the control plane and runtime build-proof check validate a build regardless
of platform. It is serialized (sorted keys, slashes unescaped) into the
`manifest` field of `CreateBuild`; `buildHash` is sent as the request's
`build_hash`. `schemaVersion` is bumped only on incompatible changes.

```jsonc
{
  "schemaVersion": "1.0",
  "platform": "ios",                 // "ios" | "android"
  "sdkVersion": "0.1.0",             // kseal SDK embedded in the build
  "buildHash": "<sha256 hex>",       // content hash of the protected build
  "versionName": "1.4.2",            // CFBundleShortVersionString / versionName
  "versionCode": 142,                // CFBundleVersion / versionCode (int64)
  "protectionProfileId": "profile-x",
  "polymorphism": {
    "seedDigest": "<sha256 hex>",    // digest of the per-build seed — never the seed
    "algorithm": "sha256-ctr"
  },
  "toolVersions": {                  // every tool that touched the build
    "ksealHarden": "0.1.0",
    "swift": "5.10.1",
    "xcodebuild": "Xcode 15.4"
  },
  "transforms": [                    // applied hardening, in order
    { "kind": "string-obfuscation", "algorithm": "seed-xor/sha256-ctr",
      "count": 2, "detail": { "enum": "KsealSecureStrings" } },
    { "kind": "symbol-strip", "algorithm": "strip", "count": 42,
      "detail": { "flags": "-x" } }
  ],
  "modules": ["string-hardening", "polymorphism", "build-proof"],
  "provenance": {
    "generatedAt": "2026-06-13T03:00:00Z",  // RFC 3339 UTC
    "generator": "kseal-harden/0.1.0",
    "host": "swiftpm-build-plugin"
  }
}
```

**Wire format note.** `CreateBuild` is served over the Connect protocol; the
client speaks Connect **JSON**. proto3-JSON rules apply: field names are
camelCase and the int64 `versionCode` is encoded as a **string** on the wire.

### `buildHash` derivation

`buildHash = SHA256( "kseal-build-hash/v1" ‖ platform ‖ sdkVersion ‖ target ‖
versionName ‖ versionCode ‖ protectionProfileId ‖ seedDigest ‖ sortedToolVersions
‖ generatedHardenedSource )`, each field length/`0x1f`-separated. Any change to
the build identity, toolchain, seed, or hardened output changes the hash, so the
proof is tightly bound to a specific protected build.

## Per-build polymorphism seed

Every build draws a fresh, high-entropy seed (platform CSPRNG via
`SystemRandomNumberGenerator`). CI may pin `KSEAL_BUILD_SEED` (hex) for
reproducible/auditable builds; otherwise it is random. The seed drives all
randomized transforms via SHA-256 in counter mode
(`block_i = SHA256(seed ‖ context ‖ i)`), with a distinct `context` per use so
material is never reused. **Only the seed digest is published** — the raw seed is
never logged, printed, or committed.

When `KSEAL_BUILD_SEED` is pinned, the build-tool plugin forwards it to
`kseal-harden` as an explicit `--build-seed` argument. This is deliberate: it
makes the seed part of the build command's cache key so SwiftPM re-hardens when
the pinned seed changes (an environment variable alone is invisible to the build
graph and would let a stale, previously hardened output be reused). The default
random-seed path passes no seed argument, so ordinary incremental builds reuse
the prior hardened output and only redraw a seed on a clean build. The pinned
value stays on the trusted build host (in the local build manifest) and is never
committed or shipped.

## String hardening

Integrators list sensitive literals in `kseal-secure-strings.json` next to their
sources:

```json
{ "apiBaseURL": "https://api.example.com", "telemetryKey": "…" }
```

At build time the plugin generates `KsealSecureStrings.generated.swift`
(compiled into the target) with one accessor per identifier. Each value is
XOR-masked with a per-entry key derived from the build's polymorphism seed, so:

- the plaintext **never appears** in the source or the linked binary (verified
  against the compiled binary in the integration test);
- a different build uses different keys, so an extracted value or a patched
  decoder does **not** transfer between builds.

Host code uses `KsealSecureStrings.apiBaseURL` instead of the literal.

## Symbol & metadata stripping

`harden-binary.sh` / `kseal-harden harden-binary` strip local and debug symbols
with `strip -x` (Mach-O and ELF), counting symbols before/after with `nm` and
validating Mach-O integrity with `otool`. Integrators also add the standard
linker dead-strip flags to *Other Linker Flags*:

```
-Xlinker -dead_strip -Xlinker -x
```

These are documented, accepted release optimizations — not private-API tricks.

## Registering the build proof

`KsealRegisterPlugin` / `kseal-harden register` reads the emitted manifest and
calls `RegistryService.CreateBuild`. Configuration comes **only from the
environment** (never flags/files), so the API key is never logged or committed:

| Variable | Purpose |
|---|---|
| `KSEAL_REGISTRY_URL` | Control-plane base URL |
| `KSEAL_API_KEY` | Bearer API key (`ksk_…`) |
| `KSEAL_TENANT_ID` / `KSEAL_APP_ID` | Tenant + app the build belongs to |
| `KSEAL_PROTECTION_PROFILE_ID` | Optional protection profile |

If the registry is unconfigured or unreachable, the proof is written to a
durable **offline artifact** (`kseal-build-proof.offline.json`) for later
reconciliation — a build never fails just because the control plane is down.

## Using the plugin

```swift
// Package.swift
.executableTarget(
    name: "App",
    plugins: [ .plugin(name: "KsealHardenPlugin", package: "KsealHarden") ]
)
```

Add `kseal-secure-strings.json` to the target's sources (exclude it from
resources). Optional build env: `KSEAL_SDK_VERSION`, `KSEAL_VERSION_NAME`,
`KSEAL_VERSION_CODE`, `KSEAL_PROTECTION_PROFILE_ID`, `KSEAL_BUILD_SEED`.

Register the proof after building:

```bash
swift package --allow-network-connections all kseal-register
```

## XCFramework pipeline

`plugins/xcode/scripts/build-xcframework.sh` packages the SDK as a hardened,
distributable XCFramework (macOS + Xcode required):

1. Build the Rust trust-core `KsealFFI.xcframework` (delegates to the SDK's
   existing `sdk/ios/scripts/build-xcframework.sh`).
2. Archive `KsealSDK` for device + simulator with
   `BUILD_LIBRARY_FOR_DISTRIBUTION=YES`.
3. `xcodebuild -create-xcframework` to combine slices.
4. Strip symbols/metadata from each slice (`harden-binary.sh`).
5. Emit the build-proof manifest (`kseal-harden generate`).
6. Register it (`kseal-harden register`) with offline fallback.

On a non-Apple host the Apple-only steps (1–4) are skipped cleanly; the
build-proof logic is still exercised by the test suite.

## App Store safety

Cross-checked against [ios-app-review.md](ios-app-review.md):

- **Public toolchain only.** Swift codegen, `strip`, `otool`, `lipo`, and
  documented linker flags. No private APIs, no `dlsym` of private symbols.
- **No dynamic code (Guideline 2.5.2).** The plugin generates source compiled at
  build time; nothing is downloaded or executed at runtime.
- **No dyld manipulation.** No `DYLD_INSERT_LIBRARIES`, no runtime dylib loading.
- **No new entitlements.** The plugin requires none beyond what the host app
  already declares.
- **Signed XCFramework.** The pipeline produces a distributable XCFramework the
  host signs as usual, preserving the SDK's privacy manifest.

## Threat model & honest limits

Consistent with the project's honest positioning
([feature-parity-matrix.md](feature-parity-matrix.md)):

- String hardening **raises the cost** of static extraction and makes bypasses
  **decay per build** via polymorphism. It is XOR masking with a seed that ships
  in the binary — it is **not** unbreakable encryption.
- The authoritative trust decision stays **server-side**. High-value secrets
  must not live on the client at all; that is what App Attest, the request-proof
  model, and the build-proof registry are for. Build hardening increases
  attacker effort and feeds the server's decaying-bypass model — it is one layer,
  not the whole defense.

## Testing

`cd plugins/xcode && swift test` runs:

- **Unit tests** (`KsealHardenCoreTests`): SHA-256 NIST vectors, seed
  determinism/keystream separation, string round-trip + plaintext absence +
  polymorphism, manifest schema/serialization, registry **wire format** against a
  mock transport (path, bearer auth, int64-as-string, manifest-as-string),
  offline fallback, and a **real `strip`** run on a freshly compiled binary.
- **Integration test** (`KsealHardenIntegrationTests`): builds
  `Fixtures/HardenedApp` with the plugin applied and asserts the manifest fields,
  the seed digest, and that the plaintext is absent from both the generated
  source and the compiled binary.

Apple-toolchain-dependent paths (`xcodebuild`, `otool`/`lipo`, the nested
fixture build when no Swift toolchain is reachable) **skip cleanly** with a clear
message rather than faking a result.
