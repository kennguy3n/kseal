using Kseal.Desktop.Pe;

namespace Kseal.Desktop;

/// <summary>Constructs the production environment for the current platform.</summary>
public static class DesktopEnvironmentFactory
{
    public static IWindowsEnvironment Create()
    {
        return OperatingSystem.IsWindows()
            ? new WindowsEnvironment()
            : new NonWindowsEnvironment();
    }
}

/// <summary>
/// Benign environment used when running on a non-Windows host (Linux CI / dev).
/// Every accessor reports "nothing observed" so the package runs and the
/// platform-independent probe logic can be unit-tested with a fake instead.
/// </summary>
internal sealed class NonWindowsEnvironment : IWindowsEnvironment
{
    public AuthenticodeInfo VerifyAuthenticode() => AuthenticodeInfo.Unsigned;
    public PeImage? LoadMainModulePe() => null;
    public IReadOnlyList<string> ForeignLoadedModulePaths() => [];
    public bool IsDebuggerAttached() => false;
    public string? ExecutablePath => null;
}
