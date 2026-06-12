# sdk/ios

iOS SDK (Swift/ObjC).

Provides the public SDK surface and the native [RASP probes](../../ARCHITECTURE.md#runtime-protection-modules) for iOS. Platform-specific probes (jailbreak/injection detection, `sysctl`/`ptrace(PT_DENY_ATTACH)` debugger checks, dyld image scanning, Secure Enclave/Keychain binding) live here in Swift/ObjC, while shared trust logic is delegated to the [Rust trust core](../rust-core) over a C ABI / UniFFI boundary.

Integrates with [App Attest + DeviceCheck](../../ARCHITECTURE.md#ios--app-attest--devicecheck) for server-side attestation. Uses **no private/undocumented APIs** to stay App Review safe, and ships an [iOS privacy manifest generator](../../ARCHITECTURE.md#store-compliance).

**Performance budget:** binary slice < 800 KB, startup overhead < 40 ms p95. **Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md) (Phase 1+).
