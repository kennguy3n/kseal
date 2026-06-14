# Changelog — kseal rust-core

All notable changes to the shared Rust trust core and its C ABI (`kseal-ffi`)
are documented here. This project adheres to
[Semantic Versioning](https://semver.org) and the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

**Minimum toolchain:** Rust 1.74. **ABI policy:** the C ABI (`kseal.h`) is
**additive-only** — existing functions, `KsealStatus` values, and struct
layouts never change meaning; new capability ships as new functions.

## [Unreleased]

### Added
- `QUICKSTART.md` — a guide for embedding the C ABI directly (new platform
  bindings / C hosts), including the `KsealStatus` → SDK error-taxonomy mapping
  that the platform SDKs now implement.

### Notes
- No C ABI changes in this release. The platform SDKs (iOS, macOS, Android,
  Windows) added typed error taxonomies that map `KsealStatus` one-to-one; the
  status codes themselves are unchanged.

## [0.1.0]

- Initial trust core: policy evaluation and local risk scoring, event
  normalization, request-proof and attestation crypto, deterministic
  serialization, and zstd batching — exposed over a stable C ABI for the
  platform SDKs.
