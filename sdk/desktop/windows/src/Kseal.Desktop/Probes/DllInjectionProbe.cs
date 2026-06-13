namespace Kseal.Desktop;

/// <summary>
/// Detects DLL injection: loaded modules that originate from neither the
/// application directory nor the operating system. This is the Windows analogue
/// of the mobile hooking signal.
/// </summary>
public sealed class DllInjectionProbe(IWindowsEnvironment env) : IProbe
{
    public string Id => "windows.dllInjection";

    public IReadOnlySet<RiskSignal> Evaluate()
    {
        var signals = new HashSet<RiskSignal>();
        if (env.ForeignLoadedModulePaths().Count > 0)
        {
            signals.Add(RiskSignal.Hooking);
        }
        return signals;
    }
}
