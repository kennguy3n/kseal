# sdk/desktop/windows

Windows desktop SDK (.NET).

Provides the public SDK surface and native desktop [RASP probes](../../../ARCHITECTURE.md#rasp-probes)
for Windows: Authenticode signature/timestamp verification (`WinVerifyTrust` +
`SignedCms`), integrity checks, MDM/GPO-delivered enterprise policy, and
hardware-bound (DPAPI/TPM) proof keys. Shared trust logic is delegated to the
[Rust trust core](../../rust-core) over the C ABI. Server-side trust decisions
are made by the kseal control plane — never the client.

The package targets `net8.0` (not `net8.0-windows`) so the cross-platform
integrity logic builds and unit-tests on any host; Windows-only Win32 calls are
guarded by `[SupportedOSPlatform]` / `OperatingSystem.IsWindows()`.

**Minimum platform:** .NET 8.0 (Windows 10 1809+ for the Windows-only probes).

## Get secure fast

New here? Follow [QUICKSTART.md](QUICKSTART.md) to integrate in ~5 minutes. See
[CHANGELOG.md](CHANGELOG.md) for versions and the typed error taxonomy
([`KsealErrorCode`](src/Kseal.Desktop/TrustCore.cs)).
