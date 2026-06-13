namespace Kseal.Desktop;

/// <summary>
/// Detects an attached debugger. Disabled by default: per the desktop threat
/// model (ARCHITECTURE.md "desktop caution"), debugging is a legitimate
/// developer/admin activity far more often than on mobile, so aggressive
/// anti-debug causes false positives early on. Integrators opt in explicitly via
/// <c>EnabledProbes</c>.
/// </summary>
public sealed class DebuggerProbe(IWindowsEnvironment env) : IProbe
{
    public string Id => "windows.debugger";

    public IReadOnlySet<RiskSignal> Evaluate()
    {
        return env.IsDebuggerAttached()
            ? new HashSet<RiskSignal> { RiskSignal.Debugger }
            : new HashSet<RiskSignal>();
    }
}
