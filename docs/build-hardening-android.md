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

The plugin registers five tasks (group `kseal`). The aggregate task `ksealHarden`
runs the whole pipeline:

| Task | Cacheable | Purpose |
|------|-----------|---------|
| `ksealGeneratePolymorphismSeed` | no¹ | Derives the per-build 256-bit polymorphism seed. |
| `ksealHardenResources` | yes | R8-aware string/resource obfuscation (seals string values). |
| `ksealStripDebugMetadata` | yes | ASM-based removal of source/line/local-variable debug info. |
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

iOS (WS-C) reuses `polymorphism` and `strip-debug-metadata` and adds its own
platform-specific names; consumers must treat the `transforms` list as open and
key off `name`.

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
  addendum is comment-only.
- **Reproducible:** deterministic AES-GCM nonces (HKDF-derived per (key, context),
  one plaintext per pair) and a `created_at`-independent `build_hash` make
  identical inputs produce identical outputs.
