# sdk/android

Android SDK (Kotlin/Java + NDK).

Provides the public SDK surface and the native [RASP probes](../../ARCHITECTURE.md#rasp-probes) for Android. Platform-specific probes (root/Magisk detection, `ptrace`/`TracerPid` debugger checks, Frida/Xposed detection, Keystore/StrongBox binding) live here in Kotlin/Java + NDK, while shared trust logic is delegated to the [Rust trust core](../rust-core) over JNI/FFI.

Integrates with the [Play Integrity API](../../ARCHITECTURE.md#android--play-integrity-api) for server-side attestation.

**Minimum platform:** Android 7.0 (API 24). **Performance budget:** AAR < 500 KB, startup overhead < 40 ms p95.

## Get secure fast

New here? Follow [QUICKSTART.md](QUICKSTART.md) to integrate in ~5 minutes, and
clone the runnable sample in [`examples/android`](../../examples/android). See
[CHANGELOG.md](CHANGELOG.md) for versions and the typed error taxonomy
([`KsealException`](src/main/kotlin/io/kseal/sdk/KsealException.kt)).
