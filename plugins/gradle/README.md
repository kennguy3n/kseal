# plugins/gradle — kseal Android build-time hardening

A Gradle plugin (`io.kseal.android.harden`) that hardens an Android app **inside
the tenant's own build** — after compilation/R8, before packaging — and registers
a **build proof** with the kseal control plane. It is the Android counterpart of
the [Xcode/iOS plugin](../xcode) and emits the same platform-neutral
`kseal.build-proof/v1` manifest.

Runs **locally in your CI** — no per-build cloud compute, no source upload. Full
design, manifest schema and App-Store/Play-safety rationale:
[`docs/build-hardening-android.md`](../../docs/build-hardening-android.md).

## What it does

Each step is an incremental, cacheable Gradle task; the umbrella `ksealHarden`
task runs the whole pipeline:

| Task | Does |
|---|---|
| `ksealGeneratePolymorphismSeed` | Derives the per-build [polymorphism](#polymorphism--reproducible-builds) seed (the single root of entropy for every randomized transform). |
| `ksealStripDebugMetadata` | Removes source-file, line-number and local-variable debug metadata from compiled classes. |
| `ksealObfuscateBytecode` | R8/mapping-aware [bytecode obfuscation](#obfuscation) — string-constant encryption + optional opaque predicates. Off by default. |
| `ksealHardenResources` | Encrypts tenant-flagged string/resource values; keeps R8 `mapping.txt` resolvable for crash symbolication. |
| `ksealHardenNativeLibraries` | Verifies the [native exploit-mitigation posture](#native-verification) (RELRO/BIND_NOW, NX, PIE, stack canary, FORTIFY, CFI, MTE, BTI/PAC) of every `.so` and records it in the proof. |
| `ksealBuildProofManifest` | Computes the reproducible `build_hash` and writes the [build-proof manifest](#build-proof-manifest). |
| `ksealRegisterBuild` | Registers the proof via `RegistryService.CreateBuild`, or stages it for later upload in [offline mode](#registry). |
| `ksealMasvsReport` | *(opt-in)* Generates the MASVS evidence report from the proof. |
| **`ksealHarden`** | Runs the full pipeline end-to-end. |

The pipeline is **fail-safe by default**: obfuscation is off, the seed is derived
deterministically, and registration runs offline unless you configure an endpoint
— so applying the plugin never breaks a build or silently weakens it.

## Quick start

```kotlin
// app/build.gradle.kts
plugins {
    id("com.android.application")
    id("io.kseal.android.harden") version "0.1.0"
}

ksealHarden {
    // App identity is auto-filled from AGP; override only in non-AGP/manual mode.
    keepStringKeys.add("app_name")          // resource keys that must stay in clear

    registry {
        endpoint.set("https://control.kseal.io")
        tenantId.set("acme")
        appId.set("checkout-android")
        // API key comes from a Gradle property (kseal.apiKey) or env var (KSEAL_API_KEY).
    }
}
```

```bash
# Harden + register as part of your release build:
./gradlew ksealHarden -Pkseal.apiKey="$KSEAL_API_KEY"

# Or run offline (writes an uploadable manifest, no network):
./gradlew ksealHarden          # offline is implied when no endpoint is set
```

When `com.android.application` is applied, the package id, version, post-R8
classes, merged resources, `mapping.txt` and keep rules are **wired
automatically**. The manual input properties below let the same tasks run in
plain modules / specialised pipelines (this is what the functional tests use).

## Configuration reference

Every option, its default, and when to change it. All properties are lazy Gradle
`Property`/`ListProperty`/file types — set them with `.set(...)` / `.add(...)` /
`.from(...)`.

### Top level — `ksealHarden { … }`

| Option | Type | Default | Purpose |
|---|---|---|---|
| `enabled` | `Boolean` | `true` | Master switch. When `false` the plugin registers no work (the tasks no-op). |
| `injectSdk` | `Boolean` | `true` | Add the kseal Android SDK as a dependency of the app. |
| `sdkGroup` / `sdkName` / `sdkVersion` | `String` | `io.kseal` / `kseal-android` / *plugin version* | Coordinates of the injected SDK. Override to pin a specific SDK build. |
| `packageId` | `String` | *(from AGP)* | App application id. Recorded in the proof; auto-filled under AGP. |
| `versionName` / `versionCode` | `String` / `Long` | *(from AGP)* | App version. Recorded in the proof and sent at registration. |
| `keepRuleFiles` | files | *(from AGP)* | ProGuard/R8 keep-rule files; their `-keep*` directives are honoured so kept symbols/resources are never obfuscated. |
| `keepStringKeys` | `List<String>` | `[]` | Extra string-resource keys (glob-capable, e.g. `url_*`) that must never be encrypted. |
| `mappingFile` | file | *(from AGP)* | R8 `mapping.txt`. Preserved verbatim at the top of the composed mapping so crash symbolication keeps working. |
| `resourcesDir` | dir | *(from AGP)* | Merged resources root to harden (manual mode). |
| `classesDirs` | files | *(from AGP)* | Compiled-classes roots to harden (manual mode). |
| `nativeLibsDirs` | files | *(unset)* | Roots containing `<abi>/lib*.so` (e.g. merged `jniLibs`). Each `.so` is verified and recorded. Left to the DSL so the plugin never guesses AGP's version-specific intermediate layout — see [native verification](#native-verification). |

### `polymorphism { … }` — reproducible builds

Controls the per-build seed. The security goal: a bypass crafted against one
shipped build does not transfer to the next. The performance goal: identical
inputs derive an identical seed, so the hardening tasks stay cacheable and
`UP-TO-DATE`.

| Option | Type | Default | Purpose |
|---|---|---|---|
| `explicitSeedHex` | `String` | *(unset)* | A pinned **64-hex-char (32-byte)** seed for fully reproducible builds/tests. Validated up front — a wrong length or non-hex value fails with an actionable message. Generate with `openssl rand -hex 32`. |
| `randomize` | `Boolean` | `false` | Fresh CSPRNG seed every build (maximum polymorphism). The seed task then **never** caches/`UP-TO-DATE`s and the build is intentionally **not** reproducible. |
| `masterKeyProperty` / `masterKeyEnv` | `String` | `kseal.polySeedKey` / `KSEAL_POLY_SEED_KEY` | Names of the Gradle property / env var holding a per-tenant master key (hex) mixed into seed derivation, so the seed is unpredictable to an attacker yet deterministic for identical inputs. **Never** stored in the manifest. |

**Seed resolution order:** `explicitSeedHex` → `randomize` → `HKDF(master key
or inputs digest, salt = group:project, info = inputs digest)`. With a master key
the seed is unpredictable yet reproducible; without one it degrades to a
content-derived seed (lower assurance). Only the non-secret seed **digest** ever
enters the manifest or cache keys.

### `obfuscation { … }`

Bytecode control-flow obfuscation. **Off by default** and fail-safe: when
disabled the classes pass through byte-identical. Name- and mapping-preserving,
so R8's `mapping.txt` keeps resolving. kseal deliberately stops short of
VM/dispatcher virtualization.

| Option | Type | Default | Purpose |
|---|---|---|---|
| `enabled` | `Boolean` | `false` | Master switch for the pass. |
| `strength` | `String` | `low` | `low` (string-constant encryption only — the safe default), `medium` (opaque predicates on a seed-chosen subset of methods) or `high` (opaque predicates on every eligible method). Case-insensitive. An unrecognized value **fails the build** with the list of valid values rather than silently downgrading. |
| `keepStrings` | `List<String>` | `[]` | Exact string literals never encrypted (e.g. reflection / resource-lookup keys). |

### `registry { … }`

Build-proof registration (`RegistryService.CreateBuild`).

| Option | Type | Default | Purpose |
|---|---|---|---|
| `endpoint` | `String` | *(unset)* | Control-plane base URL. When unset, registration runs offline. |
| `tenantId` / `appId` | `String` | *(unset)* | Required for **online** registration; a clear error is raised if missing. |
| `protectionProfileId` | `String` | `""` | Optional protection-profile id sent with the build. |
| `offline` | `Boolean` | `false` | When `true` (or when no `endpoint` is set), the manifest is written as an uploadable artifact but not POSTed. |
| `apiKeyProperty` / `apiKeyEnv` | `String` | `kseal.apiKey` / `KSEAL_API_KEY` | Names of the Gradle property / env var holding the control-plane API key. The key is read at execution time, kept out of the task input snapshot, and **never logged**. |

### `masvsReport { … }`

Optional MASVS evidence-report generation, run after the proof is written.

| Option | Type | Default | Purpose |
|---|---|---|---|
| `enabled` | `Boolean` | `false` | Opt in to the report task. |
| `executable` | `String` | *(unset)* | Path to the built [`masvs-report`](../../tools/masvs-report) binary. The task is skipped (not failed) when unset. |
| `catalogFile` | file | `docs/masvs-mapping.md` | MASVS control-catalog markdown. |

## Polymorphism & reproducible builds

In the default (non-`randomize`) mode the entire pipeline is **byte-for-byte
reproducible**: two clean builds of identical inputs on different machines
produce the same hardened artifacts, the same seed digest and the same
`build_hash`. This is asserted by a functional test that builds the fixture in
two independent project directories and compares the proof
(`HardeningFunctionalTest."two independent clean builds … are byte-for-byte
reproducible"`). Determinism comes from:

- deterministic seed derivation (above);
- AES-256-GCM sealing with a **nonce derived from the key + payload identity**
  (not random), so identical inputs seal to identical bytes;
- stable, sorted ordering of artifacts and map entries in the manifest;
- a `build_hash` that excludes volatile fields (`created_at`, host tool
  versions, registration result).

Set `polymorphism.randomize = true` only when you explicitly want a fresh seed
per build and accept non-reproducibility.

## Native verification

`ksealHardenNativeLibraries` parses each `.so` directly (a dependency-free ELF
reader) and records, per architecture, whether each exploit mitigation is
**enabled**, **absent (a finding)**, **unsupported on this arch**, or
**indeterminate**: full vs. partial RELRO (`BIND_NOW`), non-exec stack (NX), PIE,
stack canary, FORTIFY, LLVM CFI, ARM MTE, and BTI/PAC. The plugin **verifies and
records** posture (it does not relink your libraries); the recorded posture
becomes part of the build proof so the control plane can attest it. Missing
hardening on a supported architecture is reported as a finding rather than
silently skipped.

## Build-proof manifest

`build/kseal/build-proof/manifest.json` (`kseal.build-proof/v1`) is the
immutable, registrable record of a hardened build: app + SDK identity, seed
digest + derivation, tool versions, the applied transforms, and a sorted list of
artifact SHA-256 digests. The `build_hash` is the SHA-256 of the canonical core
(identity + seed digest + transform identities + sorted artifact digests). The
v2-additive `hash_coverage` section publishes an independently recomputable
`artifacts_root` and the exact fields the hash binds; `reproducibility` records
whether the build is reproducible. See
[`docs/build-hardening-android.md`](../../docs/build-hardening-android.md) for the
authoritative schema.

## Diagnostics & troubleshooting

Every task logs a one-line lifecycle summary (seed derivation + digest, classes
stripped, strings sealed/kept, native libs verified, build hash, registration
mode). Common misconfigurations fail fast with actionable messages:

| Symptom | Cause & fix |
|---|---|
| `invalid ksealHarden { obfuscation { strength } } — unknown obfuscation strength '…'` | Typo in `obfuscation.strength`; use `off`, `low`, `medium` or `high`. |
| `polymorphism.explicitSeedHex must be exactly 64 hex characters …` | Pinned seed is the wrong length/format. Generate one with `openssl rand -hex 32`. |
| `registry.tenantId is required for online registration` (or `appId`) | Set them, or enable `registry.offline`. |
| `API key not found. Set it via the configured Gradle property or env var…` | Provide `-Pkseal.apiKey=…` / `KSEAL_API_KEY`, or run offline. |

Run with `--info` for the underlying cause and `--stacktrace` for full context.

## Build & test

```bash
cd plugins/gradle
./gradlew test            # fast JVM unit tests
./gradlew functionalTest  # TestKit: applies the plugin to fixtures end-to-end
./gradlew check           # both
```

The plugin is **configuration-cache** and **build-cache** compatible; the
functional suite asserts both, plus determinism and the diagnostics above.

## Compatibility

- Gradle 8.11+ and JDK 17.
- Android Gradle Plugin 8.7.x (soft-wired: the plugin only touches AGP types when
  `com.android.application` is applied, so it also works in plain modules).
- Backward-compatible: the default configuration produces a byte-identical build
  to previous releases; the validation above only rejects input that was already
  misconfigured.
