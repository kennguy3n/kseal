// Fixture app. The `KsealSecureStrings` enum is generated at build time by
// KsealHardenPlugin from `kseal-secure-strings.json`; the plaintext values
// never appear in this source or the compiled binary.
print("api: \(KsealSecureStrings.apiBaseURL)")
print("telemetry: \(KsealSecureStrings.telemetryKey)")
