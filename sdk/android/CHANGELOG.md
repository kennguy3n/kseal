# Changelog — kseal Android SDK

All notable changes to the Android (Kotlin) SDK are documented here. This
project adheres to [Semantic Versioning](https://semver.org) and the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

**Minimum platform:** Android 7.0 (API 24). **ABI slices:** `arm64-v8a`,
`armeabi-v7a`.

## [Unreleased]

### Added
- **Typed error taxonomy.** A public `KsealException` carrying a typed
  `KsealErrorCode` (`TRUST_TOKEN_MISSING`, `CORE_INITIALIZATION_FAILED`,
  `CONFIG_REJECTED`, `INVALID_ARGUMENT`, `DECODE_FAILED`, `CRYPTO_FAILED`,
  `TRANSPORT_FAILED`, `INTERNAL_ERROR`). `KsealErrorCode.fromStatus` mirrors the
  `kseal-ffi` C ABI status codes one-to-one.
- `QUICKSTART.md` — a "get secure fast" guide for the shortest correct
  integration path.

### Changed
- `getRequestProof` now throws `KsealException(TRUST_TOKEN_MISSING)` instead of a
  bare `IllegalStateException` when no trust token has been set.

## [0.1.0]

- Initial SDK surface: `KsealSDK.initialize`, `evaluateRisk`, `setTrustToken`,
  `getRequestProof`, telemetry (`reportEvent`/`flushTelemetry`), config refresh,
  and pinning-failure reporting, backed by the shared Rust trust core over JNI.
