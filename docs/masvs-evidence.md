# kseal — MASVS Evidence Report

This document describes the **MASVS evidence report**: a per-release artifact
that maps the hardening controls *actually shipped in a given build* to the
[OWASP MASVS](https://mas.owasp.org/MASVS/) categories, using real data from the
build-proof manifest.

Where [`docs/masvs-mapping.md`](./masvs-mapping.md) is the **catalog** (the full
set of planned controls and how they map to MASVS), this report is the
**evidence**: for one concrete build it answers "which of those controls does the
binary actually carry, and what proves it?".

- Catalog → what *should* be true (static, reviewed once).
- Evidence report → what *is* true for build `<hash>` (regenerated every build
  from the manifest).

## What the report covers

The generator ([`tools/masvs-report`](../tools/masvs-report)) reads two inputs:

1. The **build-proof manifest** emitted by the hardening plugins
   (`kseal.build-proof/v1` for Android, the Swift-Codable document for iOS). This
   is the same document registered via `RegistryService.CreateBuild`.
2. The **MASVS control catalog** (`docs/masvs-mapping.md`).

It overlays the manifest's evidence onto every catalog control and emits a
Markdown report (for humans / PRs) and a JSON report (for CI gates / dashboards).

The report is **driven by real manifest data, never a static template**: adding,
removing, or altering a control in the catalog, or changing what a build actually
applies, changes the report on the next run. The generator is zero-dependency and
offline (no network, no server call), so it is safe to run in any CI step.

### Evidence statuses

| Status | Meaning |
|---|---|
| `evidenced` | The build proof proves this control is present in this build. |
| `partial` | Some, but not full, build-time evidence (e.g. polymorphism seed present but no obfuscation transform applied). |
| `skipped` | The hardening step ran but had nothing to act on — **reported, not silently dropped** (e.g. no native libraries in the build). |
| `absent` | A build-plane control with no evidence in this build. |
| `not-applicable` | A build-plane control that does not apply to this platform (e.g. native CFI/MTE on iOS, which has no `.so` plane). |
| `informational` | Owned by another plane (runtime / server / tenant); not something the build proof can attest. Honors the MASVS-RESILIENCE framing that the authoritative decision is server-side. |

## How categories map

The build plane can only *attest* a subset of MASVS controls — the ones whose
evidence is baked into the binary at build time. Those are evaluated against the
manifest; every other catalog control is listed honestly as `informational`
(verified at runtime, on the control plane, or by the tenant). The build-attested
controls and the manifest signals that evidence them:

| MASVS category | Control (catalog objective) | Build-proof signal |
|---|---|---|
| MASVS-CODE | Memory safety in native | `native-library-harden` transform: per-`.so` CFI/MTE/BTI/PAC verification counts (Android) |
| MASVS-CODE | Build provenance | `build_hash` + schema + recorded transforms (registrable via `RegistryService.CreateBuild`) |
| MASVS-RESILIENCE | Obfuscation + polymorphism | obfuscation transforms (`string-obfuscation`, `string-resource-seal`, `symbol-strip`, `strip-debug-metadata`) + per-build polymorphism seed digest |
| MASVS-RESILIENCE | Anti-tamper / integrity | Mach-O section-hash integrity slices (iOS) **or** hashed native libraries + `build_hash` artifact binding (Android) |
| MASVS-STORAGE | No secrets in app storage | string-sealing transforms (`string-obfuscation` / `string-resource-seal`) — flagged secrets are encrypted, not shipped as plaintext |

If the catalog is edited so a rule's target control disappears (renamed/removed),
the corresponding evidence is surfaced under **Orphaned Evidence** rather than
dropped, so catalog/plugin drift is visible.

## Native-hardening matrix

The Android plugin **verifies** (it cannot inject post-link) the hardening posture
of every shipped `.so` and records it in the manifest. Applicability per target:

| Feature | aarch64 (arm64-v8a) | armeabi-v7a | x86_64 | x86 | Notes |
|---|---|---|---|---|---|
| CFI (LLVM Control-Flow Integrity) | verified | verified | verified | verified | Link-time; available on all shipped ABIs. |
| MTE (Memory-Tagging Extension) | verified | unsupported | unsupported | unsupported | ARMv8.5 hardware feature; aarch64 only. |
| BTI (Branch Target Identification) | verified | unsupported | unsupported | unsupported | AArch64 branch protection. |
| PAC (Pointer Authentication) | verified | unsupported | unsupported | unsupported | AArch64 branch protection. |

Where a feature cannot apply to a target it is recorded as `unsupported` (not
silently skipped); where it *could* apply but the marker is absent it is recorded
as `absent` — a real finding the control plane can act on.

iOS has no native `.so` plane; native memory safety comes from the audited Rust
core. Instead the iOS plugin bakes **Mach-O section-hash integrity** — per-section
SHA-256 plus a load-command-region hash, for each architecture slice — so the
runtime can detect tampering. This is public-API-only and App Store safe.

## How to run it

### Standalone (CI)

```bash
go build -o masvs-report ./tools/masvs-report
./masvs-report \
  -manifest build/kseal/build-proof/manifest.json \
  -catalog docs/masvs-mapping.md \
  -out-md build/kseal/reports/masvs-evidence.md \
  -out-json build/kseal/reports/masvs-evidence.json
```

With no `-out-*` flags the Markdown report is written to stdout. The exit code is
non-zero on malformed input (fail-closed), so a CI step can gate on it.

### Android (Gradle)

The plugin exposes an optional `ksealMasvsReport` task, wired after the build
proof and run as part of `ksealHarden` when opted in:

```kotlin
ksealHarden {
    // … existing config …
    masvsReport {
        enabled.set(true)
        executable.set("$rootDir/build/tools/masvs-report")   // built Go binary
        catalogFile.set(rootProject.file("docs/masvs-mapping.md"))
    }
}
```

Reports land in `build/kseal/reports/masvs-evidence.{md,json}`. When `enabled` is
false (the default) or no `executable` is configured, the task no-ops, so a
project that does not want the report pays nothing.

### iOS (SwiftPM / Xcode command plugin)

The `KsealMasvsReportPlugin` command plugin discovers the manifest emitted by
`KsealHardenPlugin` and runs the generator:

```bash
export KSEAL_MASVS_GENERATOR=/path/to/masvs-report   # built Go binary
export KSEAL_MASVS_CATALOG=docs/masvs-mapping.md
swift package --allow-writing-to-package-directory kseal-masvs-report \
  [--manifest <path>] [--out-dir <dir>]
```

The generator path resolves from `--generator`, then `KSEAL_MASVS_GENERATOR`,
then a `masvs-report` tool on `PATH`. By default the report is written next to the
build proof.

## Sample

A report for an Android build that hardens three native libraries (CFI on all,
MTE on the arm64 slice) and seals 12 strings produces, among others:

```
## MASVS-CODE

| MASVS objective | kseal control | Phase | Status | Evidence |
|---|---|---|---|---|
| Memory safety in native | Rust core; CFI/MTE … | P1/P3 | evidenced | verified 3 native library(ies): CFI enabled=2 absent=0 unsupported=1; MTE enabled=1 unsupported=1 (unsupported targets reported, not skipped) |
| Build provenance | Build proof records hashes/manifests; runtime verifies | P3 | evidenced | build proof "kseal.build-proof/v1" with build_hash 9f86d081884c… records 4 transform(s); registrable via RegistryService.CreateBuild for runtime verification |
```

and for an iOS build with Mach-O integrity baked:

```
## MASVS-RESILIENCE

| MASVS objective | kseal control | Phase | Status | Evidence |
|---|---|---|---|---|
| Anti-tamper / integrity | App-integrity + … build-proof binding | P2/P3 | evidenced | Mach-O section-hash integrity baked for 1 slice(s) [arm64]; load-command hashes recorded for runtime tamper detection |
```
