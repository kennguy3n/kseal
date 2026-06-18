# sdk/desktop/macos

macOS desktop SDK (Swift).

Provides the public SDK surface and native desktop [RASP probes](../../../ARCHITECTURE.md#rasp-probes)
for macOS: Authenticode-equivalent code-signature/Gatekeeper verification,
debugger/injection checks, and Secure Enclave–bound proof keys. Shared trust
logic is delegated to the [Rust trust core](../../rust-core) over a C ABI.
Server-side trust decisions are made by the kseal control plane — never the
client. Uses **only Gatekeeper-safe public APIs**.

**Minimum platform:** macOS 11 (Big Sur).

## Get secure fast

New here? Follow [QUICKSTART.md](QUICKSTART.md) to integrate in ~5 minutes, and
clone the runnable sample in [`examples/desktop-macos`](../../../examples/desktop-macos).
See [CHANGELOG.md](CHANGELOG.md) for versions and the typed error taxonomy
([`KsealErrorKind`](Sources/KsealDesktop/TrustCore.swift)).
