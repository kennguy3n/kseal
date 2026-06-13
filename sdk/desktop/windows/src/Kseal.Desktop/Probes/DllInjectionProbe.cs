namespace Kseal.Desktop;

/// <summary>
/// Detects DLL injection: loaded modules that originate from neither the
/// application directory nor the operating system. This is the Windows analogue
/// of the mobile hooking signal.
/// </summary>
/// <param name="env">Code-integrity surface to inspect.</param>
/// <param name="isAllowed">
/// Enterprise allowlist predicate; a module path it accepts is a sanctioned
/// plugin/agent and does not raise the signal. The default allows nothing,
/// preserving the strict (pre-policy) behavior.
/// </param>
public sealed class DllInjectionProbe(IWindowsEnvironment env, Func<string, bool>? isAllowed = null) : IProbe
{
    private readonly Func<string, bool> _isAllowed = isAllowed ?? (_ => false);

    public string Id => "windows.dllInjection";

    public IReadOnlySet<RiskSignal> Evaluate()
    {
        var signals = new HashSet<RiskSignal>();
        if (env.ForeignLoadedModulePaths().Any(path => !_isAllowed(path)))
        {
            signals.Add(RiskSignal.Hooking);
        }
        return signals;
    }
}
