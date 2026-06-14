# Changelog — kseal iOS SDK

All notable changes to the iOS (Swift) SDK are documented here. This project
adheres to [Semantic Versioning](https://semver.org) and the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

**Minimum platform:** iOS 13 (the package also builds for macOS 11+ for host
testing). Uses only public, App Review–safe APIs.

## [Unreleased]

### Added
- **Typed error taxonomy.** `TrustCoreError` now carries a typed
  `KsealErrorKind` (`trustTokenMissing`, `coreInitializationFailed`,
  `configRejected`, `invalidArgument`, `decodeFailed`, `cryptoFailed`,
  `transportFailed`, `internalError`) and conforms to `LocalizedError` and
  `Equatable`. `KsealErrorKind(status:)` mirrors the `kseal-ffi` C ABI status
  codes one-to-one.
- `QUICKSTART.md` — a "get secure fast" guide for the shortest correct
  integration path.

### Changed
- Errors now expose a typed `kind`; callers should branch on `error.kind`
  instead of matching the message string. The `message` field is unchanged.

## [0.1.0]

- Initial SDK surface: `KsealSDK.initialize`, `evaluateRisk`, `setTrustToken`,
  `getRequestProof`, telemetry (`reportEvent`/`flushTelemetry`), config refresh,
  and pinning-failure reporting, backed by the shared Rust trust core.
