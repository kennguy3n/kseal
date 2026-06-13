namespace Kseal.Desktop;

/// <summary>
/// Verifies the running executable's Authenticode signature: presence +
/// validity, and (when the policy configures it) the publisher, certificate
/// thumbprint, and timestamp. A broken signature is reported as tamper +
/// app-integrity; a mismatched publisher / certificate is reported as
/// repackaging.
/// </summary>
public sealed class AuthenticodeProbe(IWindowsEnvironment env, WindowsIntegrityPolicy policy) : IProbe
{
    public string Id => "windows.authenticode";

    public IReadOnlySet<RiskSignal> Evaluate()
    {
        var signals = new HashSet<RiskSignal>();
        var info = env.VerifyAuthenticode();

        if (policy.RequireValidSignature && !(info.IsSigned && info.SignatureValid))
        {
            signals.Add(RiskSignal.Tamper);
            signals.Add(RiskSignal.AppIntegrity);
        }

        if (!string.IsNullOrEmpty(policy.ExpectedPublisher) && info.Publisher != policy.ExpectedPublisher)
        {
            signals.Add(RiskSignal.Repackaged);
            signals.Add(RiskSignal.AppIntegrity);
        }

        if (!string.IsNullOrEmpty(policy.ExpectedCertificateThumbprint) &&
            !string.Equals(info.CertificateThumbprint, policy.ExpectedCertificateThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            signals.Add(RiskSignal.Repackaged);
            signals.Add(RiskSignal.AppIntegrity);
        }

        // Only assess timestamp for an otherwise-valid signature; an invalid
        // signature is already fully described above.
        if (policy.RequireTimestamp && info is { IsSigned: true, SignatureValid: true } && !info.TimestampValid)
        {
            signals.Add(RiskSignal.AppIntegrity);
        }

        return signals;
    }
}
