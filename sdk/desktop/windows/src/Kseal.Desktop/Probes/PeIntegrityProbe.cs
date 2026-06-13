namespace Kseal.Desktop;

/// <summary>
/// Verifies PE header/section integrity of the running executable: a malformed
/// or unparsable image, or (when the policy supplies it) a stripped embedded
/// signature or a section whose hash diverges from the signed-config baseline,
/// is reported as in-memory/in-file tamper.
/// </summary>
public sealed class PeIntegrityProbe(IWindowsEnvironment env, WindowsIntegrityPolicy policy) : IProbe
{
    public string Id => "windows.peIntegrity";

    public IReadOnlySet<RiskSignal> Evaluate()
    {
        var signals = new HashSet<RiskSignal>();
        var pe = env.LoadMainModulePe();

        if (pe is null || !pe.IsValid)
        {
            // A protected app that cannot read/parse its own PE is in an
            // untrustworthy state — fail closed.
            signals.Add(RiskSignal.Tamper);
            signals.Add(RiskSignal.AppIntegrity);
            return signals;
        }

        if (policy.RequireValidSignature && !pe.HasEmbeddedSignature)
        {
            // Authenticode signature directory stripped from the image.
            signals.Add(RiskSignal.Tamper);
            signals.Add(RiskSignal.AppIntegrity);
        }

        if (!string.IsNullOrEmpty(policy.ExpectedSectionSha256))
        {
            string? actual = pe.SectionSha256(policy.SectionName);
            if (!string.Equals(actual, policy.ExpectedSectionSha256, StringComparison.OrdinalIgnoreCase))
            {
                signals.Add(RiskSignal.Tamper);
            }
        }

        return signals;
    }
}
