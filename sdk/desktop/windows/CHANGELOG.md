# Changelog — kseal Windows desktop SDK

All notable changes to the Windows (.NET) desktop SDK are documented here. This
project adheres to [Semantic Versioning](https://semver.org) and the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

**Minimum platform:** .NET 8.0 (targets `net8.0`; Windows-only Authenticode and
MDM-policy reads are guarded by `[SupportedOSPlatform]` so the package still
builds/tests on any host).

## [Unreleased]

### Added
- **Typed error taxonomy.** `TrustCoreException` now exposes a typed
  `KsealErrorCode Code` (`TrustTokenMissing`, `CoreInitializationFailed`,
  `ConfigRejected`, `InvalidArgument`, `DecodeFailed`, `CryptoFailed`,
  `TransportFailed`, `InternalError`). `TrustCoreException.CodeFromStatus`
  mirrors the `kseal-ffi` C ABI status codes one-to-one.
- `QUICKSTART.md` — a "get secure fast" guide for the shortest correct
  integration path.
- Explicit `<Version>0.1.0</Version>` in the project file for semver hygiene.

### Changed
- Errors now expose a typed `Code`; callers should branch on `ex.Code` instead
  of matching the message string. Existing `catch (TrustCoreException)` sites
  are unaffected.

## [0.1.0]

- Initial SDK surface: `KsealDesktopClient.Initialize`, `EvaluateRisk`,
  `EstablishTrustSession`, `AuthorizeRequest`, `GetRequestProof`, telemetry, and
  enterprise-policy support, with hardware-bound proof keys.
