using Kseal.Desktop;
using Kseal.Desktop.Pe;

namespace Kseal.Desktop.Tests;

/// <summary>
/// Deterministic <see cref="IWindowsEnvironment"/> for unit tests: supplies
/// controlled Authenticode results, PE images, injected-module lists, and
/// debugger state without touching the real OS. This is the test fake for the
/// external OS-attestation boundary.
/// </summary>
internal sealed class FakeWindowsEnvironment : IWindowsEnvironment
{
    public AuthenticodeInfo Authenticode { get; set; } = AuthenticodeInfo.Unsigned;
    public PeImage? Pe { get; set; }
    public List<string> Foreign { get; } = [];
    public bool Debugger { get; set; }
    public string? ExecutablePath { get; set; } = "/fake/app.exe";

    public AuthenticodeInfo VerifyAuthenticode() => Authenticode;
    public PeImage? LoadMainModulePe() => Pe;
    public IReadOnlyList<string> ForeignLoadedModulePaths() => Foreign;
    public bool IsDebuggerAttached() => Debugger;
}
