using System.Text.Json;

namespace Kseal.Desktop;

/// <summary>
/// Produces the platform-attestation token submitted to <c>VerifyAttestation</c>.
///
/// This is the <b>external-attestation mock boundary</b>. Windows exposes no
/// first-party remote attestation service for arbitrary apps, so the default
/// implementation produces a <i>local</i> attestation derived from the verified
/// Authenticode identity — no network and no external dependency. An integrator
/// fronting a cloud KMS/HSM or a TPM-quote service plugs a real implementation
/// in here; tests inject a fake. The server fuses the on-device risk bitset with
/// whatever token this yields.
/// </summary>
public interface ICodeIntegrityAttestor
{
    /// <summary>
    /// Returns the attestation token bytes (empty when no external attestation
    /// is configured — the server then relies on the fused risk signals + the
    /// request-proof key binding).
    /// </summary>
    byte[] AttestationToken(AuthenticodeInfo info);
}

/// <summary>
/// Default attestor: a compact, non-PII local attestation built from the
/// verified Authenticode identity (publisher + certificate thumbprint). It
/// carries no secret and no personal data — only the signing provenance the
/// server can cross-check against the registered build.
/// </summary>
public sealed class LocalCodeIntegrityAttestor : ICodeIntegrityAttestor
{
    public byte[] AttestationToken(AuthenticodeInfo info)
    {
        // Empty unless the binary is validly signed: an unsigned/invalid binary
        // has no provenance to attest, so we send nothing and let the fused risk
        // signals drive the server decision (fail-closed on the server side).
        if (!info.IsSigned || !info.SignatureValid) return [];

        var fields = new SortedDictionary<string, string>();
        if (info.Publisher is not null) fields["publisher"] = info.Publisher;
        if (info.CertificateThumbprint is not null) fields["thumbprint"] = info.CertificateThumbprint;
        fields["timestamped"] = info.TimestampValid ? "1" : "0";
        return JsonSerializer.SerializeToUtf8Bytes(fields);
    }
}
