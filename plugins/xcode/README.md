# plugins/xcode — kseal iOS build-time hardening

XCFramework packaging + a SwiftPM/Xcode **build-tool plugin** that hardens an iOS
app at build time and registers a **build proof** with the kseal control plane —
the iOS counterpart of the Android/Gradle plane (WS-B).

Runs **locally in the tenant's CI** — no per-build cloud compute. Full design,
manifest schema, and App Store-safety rationale:
[`docs/build-hardening-ios.md`](../../docs/build-hardening-ios.md).

## What it does

- **String hardening** — replaces tenant-flagged literals with per-build
  obfuscated accessors; plaintext never appears in source or binary.
- **Per-build polymorphism** — fresh CSPRNG seed per build drives all randomized
  transforms (SHA-256 CTR); bypasses decay across builds.
- **Symbol & metadata stripping** — `strip -x` + linker dead-strip
  (`strip`/`nm`/`otool`, public toolchain only).
- **Build-proof manifest** — canonical schema shared with Android (build hash,
  seed digest, tool versions, SDK version, transforms).
- **Registration** — `RegistryService.CreateBuild` over Connect JSON; API key
  from env, with a durable offline artifact fallback.

App Store safe by construction: public APIs only, no dynamic code, no dyld
manipulation, no added entitlements (see
[`docs/ios-app-review.md`](../../docs/ios-app-review.md)).

## Package layout

| Product | Kind | Responsibility |
|---|---|---|
| `KsealHardenCore` | library | Portable, zero-dependency hardening logic (seed, strings, symbols, manifest, registry client). |
| `kseal-harden` | executable | Build-tool CLI: `generate`, `register`, `harden-binary`, `version`. |
| `KsealHardenPlugin` | build-tool plugin | Build-time string hardening + proof emission (no network). |
| `KsealRegisterPlugin` | command plugin | Registers the proof (network-permitted) + offline fallback. |

```
plugins/xcode/
├── Package.swift
├── Sources/
│   ├── KsealHardenCore/        # SHA256, PolymorphismSeed, StringHardener,
│   │                           # SymbolHardener, BuildProofManifest, RegistryClient, HardenEngine
│   └── kseal-harden/           # CLI entrypoint
├── Plugins/
│   ├── KsealHardenPlugin/      # build-tool plugin
│   └── KsealRegisterPlugin/    # command plugin
├── Fixtures/HardenedApp/       # fixture package used by the integration test
├── Tests/
│   ├── KsealHardenCoreTests/        # unit tests
│   └── KsealHardenIntegrationTests/ # builds the fixture with the plugin applied
└── scripts/
    ├── build-xcframework.sh    # full XCFramework pipeline (macOS/Xcode)
    └── harden-binary.sh        # strip + verify a single binary
```

## Quick start

Apply the build-tool plugin to a target and list secrets to harden:

```swift
// Package.swift
.executableTarget(
    name: "App",
    exclude: ["kseal-secure-strings.json"],
    plugins: [ .plugin(name: "KsealHardenPlugin", package: "KsealHarden") ]
)
```

```json
// Sources/App/kseal-secure-strings.json
{ "apiBaseURL": "https://api.example.com", "telemetryKey": "…" }
```

Use the generated accessor (`KsealSecureStrings.apiBaseURL`) instead of the
literal. Register the emitted proof:

```bash
export KSEAL_REGISTRY_URL=… KSEAL_API_KEY=… KSEAL_TENANT_ID=… KSEAL_APP_ID=…
swift package --allow-network-connections all kseal-register
```

Package the SDK as a hardened XCFramework (macOS + Xcode):

```bash
plugins/xcode/scripts/build-xcframework.sh
```

## Tests

```bash
cd plugins/xcode && swift test
```

Unit tests run on any Swift toolchain (incl. Linux). Apple-toolchain-dependent
paths skip cleanly with a clear message rather than faking a result. See the
[testing section](../../docs/build-hardening-ios.md#testing) for details.
