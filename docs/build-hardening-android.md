# Android build hardening & the build-proof manifest

The kseal Gradle plugin (`io.kseal.android.harden`, sources under
[`plugins/gradle/`](../plugins/gradle)) hardens an Android app at build time and
emits a **build-proof manifest** that is registered with the control plane via
`RegistryService.CreateBuild`. The manifest is the immutable record of *what* a
hardened build is and *how* it was produced; the runtime SDK and the registry use
it to verify binary integrity during attestation.

This document is the **authoritative, platform-neutral schema** for the manifest.
The iOS Xcode plugin (WS-C) emits the **same** `kseal.build-proof/v1` document,
differing only in `platform` and the platform-specific `transforms[].name`
values. Keep both platforms in lock-step with this file.

## Pipeline overview

The plugin registers the tasks below (group `kseal`). The aggregate task
`ksealHarden` runs the whole pipeline:

| Task | Cacheable | Purpose |
|------|-----------|---------|
| `ksealGeneratePolymorphismSeed` | no¹ | Derives the per-build 256-bit polymorphism seed. |
| `ksealStripDebugMetadata` | yes | ASM-based removal of source/line/local-variable debug info. |
| `ksealObfuscateBytecode` | yes | Per-build, seed-driven DEX/JVM-bytecode obfuscation (string-constant encryption + opaque predicates). Default **off**. |
| `ksealHardenResources` | yes | R8-aware string/resource obfuscation (seals string values). |
| `ksealHardenNativeLibraries` | yes | Parses bundled `.so` files and records a real per-binary native posture. |
| `ksealBuildProofManifest` | yes | Assembles the manifest and computes `build_hash`. |
| `ksealRegisterBuild` | no² | Registers the proof via `CreateBuild`, or stages it offline. |

¹ The seed is sensitive and is never pushed to a shared cache. A *derived* seed is
still `UP-TO-DATE` when inputs are unchanged; a *random* seed (`polymorphism.randomize = true`)
re-runs every build by design.
² Registration is a network side effect and must never be served from a cache. It
is still locally `UP-TO-DATE` when the manifest is unchanged, so a no-op rebuild
does not re-POST.

All other tasks declare precise `@Input`/`@InputFile`/`@OutputFile` wiring with
`@PathSensitive` normalization, so they are incremental, `UP-TO-DATE`-aware, and
restored `FROM-CACHE` on a clean rebuild with unchanged inputs. The pipeline is
configuration-cache compatible.

## Manifest schema (`kseal.build-proof/v1`)

A manifest is a UTF-8 JSON object with insertion-ordered keys (stable, diff- and
reproducibility-friendly). Top-level shape:

| Field | Type | In `build_hash`? | Description |
|-------|------|------------------|-------------|
| `schema` | string | yes | Constant `"kseal.build-proof/v1"`. |
| `platform` | string | yes | `"android"` or `"ios"`. |
| `build_hash` | string (hex) | — | SHA-256 over the canonical core (see below). Binds the proof to the produced content. |
| `created_at` | string (RFC 3339 / ISO-8601, second precision) | **no** | Wall-clock time the manifest was assembled. Volatile; excluded from `build_hash`. |
| `app` | object | yes | App identity. |
| `app.package_id` | string | yes | Android package name / iOS bundle id. |
| `app.version_name` | string | yes | Human version (e.g. `1.4.2`). |
| `app.version_code` | number (int64) | yes | Monotonic build number. |
| `sdk` | object | yes | kseal runtime SDK linked into the app. |
| `sdk.name` | string | yes | e.g. `kseal-android`. |
| `sdk.version` | string | yes | e.g. `0.1.0`. |
| `seed` | object | partial | Polymorphism seed provenance. |
| `seed.digest` | string (hex) | yes | SHA-256 of the per-build seed. The seed itself is **never** emitted. |
| `seed.algorithm` | string | no | Key-derivation algorithm, `"HKDF-SHA256"`. |
| `seed.derivation` | string | no | `explicit` \| `random` \| `content` \| `master-key`. |
| `tooling` | object | **no** | Host toolchain versions (plugin, gradle, java, asm, `r8_mapping`). Volatile; excluded from `build_hash`. |
| `transforms` | array<object> | yes (name+status only) | Hardening transforms applied, sorted by `name`. |
| `transforms[].name` | string | yes | Transform id (see below). |
| `transforms[].status` | string | yes | `"applied"` \| `"skipped"`. |
| `transforms[].details` | object | no | Free-form per-transform counters/metadata. |
| `artifacts` | array<object> | yes | Content digests of hardened outputs, sorted by `path`. |
| `artifacts[].path` | string | yes | Logical path (e.g. `classes/...`, `res/...`, `mapping.txt`). |
| `artifacts[].sha256` | string (hex) | yes | SHA-256 of the file content. |
| `registration` | object | no | Present only in the staged/uploadable copy when applicable. |

### `transforms[].name` values (Android)

- `polymorphism` — per-build seed-driven randomization (`details.algorithm`, `details.derivation`).
- `string-resource-seal` — AES-256-GCM sealing of string-resource values (`details.sealed_count`, `details.kept_count`, `details.tokens`).
- `strip-debug-metadata` — debug-info removal (`details.classes_stripped`, `details.files_copied`).
- `bytecode-control-flow-obfuscation` — per-build IR/bytecode transform (`details.strength`, `details.classes_processed`, `details.unique_strings_encrypted`, `details.string_loads_rewritten`, `details.methods_with_opaque_predicate`, `details.opaque_predicates_inserted`, `details.decoder_class`). `status` is `"disabled"` when the feature is off (the default), so default builds remain byte-identical.
- `native-library-harden` — per-binary native posture (`details.library_count`, `details.summary`). `status` is `"skipped"` when the app bundles no `.so` files.

iOS (WS-C) reuses `polymorphism` and `strip-debug-metadata` and adds its own
platform-specific names (e.g. `string-obfuscation`, `symbol-strip`,
`macho-section-integrity`, `macho-binary-posture`); consumers must treat the
`transforms` list as open and key off `name`.

### Bytecode obfuscation pass (per-build polymorphism)

`ksealObfuscateBytecode` runs **after** debug-stripping and **before** R8, on the
JVM/DEX bytecode (via ASM). It applies two seed-driven transforms while preserving
every class/method/field name and signature so the R8 mapping — and therefore crash
symbolication — survives unchanged:

- **String-constant encryption.** Each `String` literal load is replaced by a call
  into a generated decoder class. Plaintext is XOR-encrypted with a keystream
  derived deterministically from the per-build seed (`SHA-256(seed ‖ index ‖ ctr)`),
  so the cleartext never appears in the constant pool, and two builds with different
  seeds produce different ciphertext (the "decaying bypass" model).
- **Opaque predicates.** Always-true relations (`c == c`, `c < c + 1`, `c >= 0`)
  guard never-taken blocks, frustrating static control-flow recovery. The bytecode
  stays verifiable under the JVM verifier.

Strength is configurable and **defaults to off**; when enabled it defaults to `low`:

| Strength | String encryption | Opaque predicates |
|----------|-------------------|-------------------|
| `off` (default) | — | — |
| `low` | yes (len ≥ 4) | — |
| `medium` | yes (len ≥ 3) | ~35 % of methods |
| `high` | yes (len ≥ 2) | every eligible method |

**Why we stop short of VM/dispatcher virtualization.** kseal deliberately avoids
heavyweight bytecode-VM obfuscation (the DexGuard/iXGuard "virtualization" axis): it
inflates size and startup well past our budgets (SDK startup < 40 ms, footprint
< 3–5 MB), is brittle across ART/Dalvik and OS versions, and breaks reliable
symbolication — all at odds with serving 5000 SME tenants. We instead lean on
**per-build polymorphism + native verification + mapping-aware integration**, where
a bypass crafted for one build does not transfer to the next. See
[`ARCHITECTURE.md#what-to-avoid`](../ARCHITECTURE.md).

### Native posture (`ksealHardenNativeLibraries`)

Bundled `.so` files are parsed (real ELF parsing — program headers, `.dynamic`,
symbol tables) to produce a **per-binary posture** rather than an assertion. Each
binary reports a status of `enabled` / `absent` / `unsupported` / `indeterminate`
for: **RELRO** (full/partial), **stack canary**, **FORTIFY**, **NX** (`GNU_STACK`),
**PIE**, and the CFI/PAC/BTI/MTE control-flow signals, across `arm64`, `arm`,
`x86_64` and `x86`. The report is recorded under the `native-library-harden`
transform `details.summary` and surfaced per-architecture.

### The build hash

`build_hash = SHA-256( canonical-core-json )` where the canonical core is the
compact (no-whitespace) JSON of:

```
{
  "schema": "...",
  "platform": "...",
  "app": { "package_id", "version_name", "version_code" },
  "sdk": { "name", "version" },
  "seed_digest": "<hex>",
  "transforms": [ { "name", "status" }, ... ],          // input order, name/status only
  "artifacts":  [ { "path", "sha256" }, ... ]           // sorted by path
}
```

It **deliberately excludes** `created_at`, `tooling`, `seed.algorithm/derivation`,
`transforms[].details`, and `registration`. As a result the hash is **reproducible
across machines** for identical inputs, while still binding to every byte of the
hardened artifacts.

### Example

```json
{
  "schema": "kseal.build-proof/v1",
  "platform": "android",
  "build_hash": "9f2c…",
  "created_at": "2026-06-13T03:00:00Z",
  "app": {
    "package_id": "com.example.app",
    "version_name": "1.4.2",
    "version_code": 142
  },
  "sdk": { "name": "kseal-android", "version": "0.1.0" },
  "seed": {
    "digest": "5b1e…",
    "algorithm": "HKDF-SHA256",
    "derivation": "content"
  },
  "tooling": {
    "plugin": "io.kseal.android.harden:0.1.0",
    "gradle": "8.11.1",
    "java": "17.0.10",
    "asm": "9.7.1",
    "r8_mapping": true
  },
  "transforms": [
    { "name": "polymorphism", "status": "applied",
      "details": { "algorithm": "HKDF-SHA256", "derivation": "content" } },
    { "name": "string-resource-seal", "status": "applied",
      "details": { "sealed_count": 1, "kept_count": 1, "tokens": { "kseal_…": "api_secret" } } },
    { "name": "strip-debug-metadata", "status": "applied",
      "details": { "classes_stripped": 12, "files_copied": 3 } }
  ],
  "artifacts": [
    { "path": "assets/kseal/strings.sealed", "sha256": "a1…" },
    { "path": "mapping.txt", "sha256": "b2…" },
    { "path": "res/values/strings.xml", "sha256": "c3…" }
  ]
}
```

## Build-proof v2 (additive, backward-compatible)

The manifest carries a `manifest_revision` (currently `2`) **within** the unchanged
`kseal.build-proof/v1` schema. v2 only *adds* sections; the `schema` id, the
`build_hash` core inputs, and every v1 field are untouched, so existing consumers
(and v1-only verifiers) keep working — they simply ignore the new keys.

| Field | Type | In `build_hash`? | Description |
|-------|------|------------------|-------------|
| `manifest_revision` | number | **no** | Additive content revision (`2`). Volatile; not part of the hash core. |
| `hash_coverage` | object | no | Auditable description of what the hash binds. |
| `hash_coverage.algorithm` | string | no | `"sha256"`. |
| `hash_coverage.artifact_count` | number | no | Number of hashed artifacts. |
| `hash_coverage.by_category` | object | no | Per-plane file counts (keyed by the path's first segment). |
| `hash_coverage.artifacts_root` | string (hex) | no | **Independently verifiable** SHA-256 over the sorted `path\u0000sha256` lines. A holder of the hardened artifacts can recompute this to confirm the manifest covers exactly that set — no silent gaps. |
| `hash_coverage.covered_fields` | array<string> | no | The manifest regions the `build_hash` integrity-protects. |
| `hash_coverage.complete` | bool | no | True when ≥1 artifact is covered. |
| `reproducibility` | object | no | Reproducibility posture. |
| `reproducibility.reproducible` | bool | no | True unless the seed was randomized (max-polymorphism observe mode is intentionally non-reproducible). |
| `reproducibility.seed_derivation` | string | no | `explicit` \| `random` \| `content` \| `master-key`. |
| `reproducibility.build_hash_algorithm` | string | no | `"sha256"`. |

**Platform alignment.** iOS emits the conceptually identical v2 sections
(`manifestRevision`, `hashCoverage`, `reproducibility`, plus a `posture` block) using
its existing camelCase Codable key style; the iOS `hashCoverage.artifactsRoot` is the
same independent-root idea computed over the parsed Mach-O slices/sections. Both
platforms keep `schemaVersion`/`schema` = `1.0`/`kseal.build-proof/v1` and treat the
v2 keys as optional, so a manifest written by either plugin still decodes on the
other's revision-1 reader.

## Registration (`RegistryService.CreateBuild`)

`ksealRegisterBuild` POSTs a Connect-protocol JSON request to
`<endpoint>/kseal.v1.RegistryService/CreateBuild`:

```json
{
  "tenant_id": "...",
  "app_id": "...",
  "build_hash": "<manifest.build_hash>",
  "version_name": "<manifest.app.version_name>",
  "version_code": "142",          // int64 → JSON string per protobuf-JSON mapping
  "protection_profile_id": "...",
  "manifest": "<the full manifest JSON, as a string>"
}
```

- **Auth:** the API key is sent as `Authorization: Bearer <key>`. It is read from a
  Gradle property or environment variable (configurable; defaults
  `kseal.apiKey` / `KSEAL_API_KEY`), kept `@Internal` so it never enters a task
  input snapshot or the build cache, and is never logged.
- **Response:** `{ "build": { "id": "..." } }`; the build id is written to the
  registration receipt.
- **Fail-closed / offline:** if `registry.offline = true`, the endpoint is unset,
  or required ids/key are missing in online mode, the task writes the manifest to
  `build/kseal/build-proof/uploadable-manifest.json` plus an offline receipt for
  later upload — it does not silently "succeed" against the network.

### Output locations (under `build/kseal/`)

- `seed/seed-digest.txt`, `seed/seed-meta.json` — seed digest & provenance (the raw `seed/seed.hex` is written with `0600` permissions and never registered).
- `hardened/res/…` — hardened resources; `hardened/assets/kseal/strings.sealed` — sealed string blob.
- `hardened/mapping.txt` — original R8 mapping preserved **verbatim**, followed by a kseal addendum (comment lines) so standard `retrace` works unchanged.
- `build-proof/manifest.json`, `build-proof/build-hash.txt`.
- `build-proof/registration-receipt.json`, `build-proof/uploadable-manifest.json`.

## Configuration (DSL)

```kotlin
ksealHarden {
    injectSdk.set(true)                       // link io.kseal:kseal-android:<version>
    keepStringKeys.add("app_name")            // resource names whose values stay in clear
    keepRuleFiles.from("proguard-rules.pro")  // reflection/serialization keep-rules are honoured
    obfuscation {
        enabled.set(false)                    // default off => byte-identical default builds
        strength.set("low")                   // low | medium | high (when enabled)
        keepStrings.add("com.example.Reflected") // literals never encrypted
    }
    polymorphism {
        randomize.set(false)                  // true => fresh seed every build (non-reproducible)
        // explicitSeedHex / masterKeyProperty / masterKeyEnv also supported
    }
    registry {
        endpoint.set("https://api.kseal.example")
        tenantId.set("…"); appId.set("…"); protectionProfileId.set("…")
        offline.set(false)                    // true => stage manifest, skip network
        // apiKeyProperty / apiKeyEnv select where the secret is read from
    }
}
```

When `com.android.application` is applied, the plugin soft-wires `packageId`,
`versionName`, `versionCode`, and the R8 `mappingFile` from the release variant
automatically; the values above are otherwise set explicitly.

## Safety guarantees

- **Does not break the app:** only string-resource *values* are sealed (never
  resource names/ids), fully-qualified class-name values are left in clear, and
  keep-rule-matched names are preserved — reflection/serialization keep working.
- **Crash symbolication intact:** the R8 mapping is preserved verbatim; the kseal
  addendum is comment-only. The bytecode obfuscation pass is name- and
  signature-preserving (it transforms method bodies only), so `mapping.txt` keeps
  resolving and `retrace` works unchanged.
- **Default builds are byte-identical:** bytecode obfuscation is off by default and
  resolves to a pass-through copy, so enabling kseal does not perturb default output.
- **Reproducible:** deterministic AES-GCM nonces (HKDF-derived per (key, context),
  one plaintext per pair) and a `created_at`-independent `build_hash` make
  identical inputs produce identical outputs.
