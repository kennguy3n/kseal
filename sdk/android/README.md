# sdk/android

Android SDK (Kotlin/Java + NDK).

Provides the public SDK surface and the native [RASP probes](../../ARCHITECTURE.md#runtime-protection-modules) for Android. Platform-specific probes (root/Magisk detection, `ptrace`/`TracerPid` debugger checks, Frida/Xposed detection, Keystore/StrongBox binding) live here in Kotlin/Java + NDK, while shared trust logic is delegated to the [Rust trust core](../rust-core) over JNI/FFI.

Integrates with the [Play Integrity API](../../ARCHITECTURE.md#android--play-integrity-api) for server-side attestation.

**Performance budget:** AAR < 500 KB, startup overhead < 40 ms p95. **Status:** scaffold — see [PROGRESS.md](../../PROGRESS.md) (Phase 1+).
