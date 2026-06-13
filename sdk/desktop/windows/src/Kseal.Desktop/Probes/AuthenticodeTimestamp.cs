using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Kseal.Desktop;

/// <summary>
/// Detects a trusted-timestamp countersignature inside an Authenticode PKCS#7
/// <c>SignedData</c> blob. A timestamp (issued by a Timestamping Authority when
/// the signature was created) lets the signature stay valid after the signing
/// certificate expires, so its presence — not the certificate's own validity
/// window — is the correct signal to surface.
///
/// Pure managed (<see cref="SignedCms"/>); runs on any host, so it is fully
/// unit-testable off Windows.
/// </summary>
internal static class AuthenticodeTimestamp
{
    // PKCS#9 counter-signature (legacy Authenticode timestamp).
    private const string CounterSignatureOid = "1.2.840.113549.1.9.6";
    // RFC 3161 signature-time-stamp-token (modern Authenticode timestamp).
    private const string Rfc3161TimestampOid = "1.2.840.113549.1.9.16.2.14";

    /// <summary>
    /// True when <paramref name="pkcs7"/> carries a legacy PKCS#9 countersignature
    /// or an RFC 3161 timestamp token as an unsigned attribute of any signer.
    /// </summary>
    public static bool HasTrustedTimestamp(byte[]? pkcs7)
    {
        if (pkcs7 is null || pkcs7.Length == 0) return false;
        try
        {
            var cms = new SignedCms();
            cms.Decode(pkcs7);
            foreach (SignerInfo signer in cms.SignerInfos)
            {
                // SignedCms surfaces legacy PKCS#9 countersignatures here.
                if (signer.CounterSignerInfos.Count > 0) return true;
                foreach (CryptographicAttributeObject attr in signer.UnsignedAttributes)
                {
                    string? oid = attr.Oid?.Value;
                    if (oid is Rfc3161TimestampOid or CounterSignatureOid) return true;
                }
            }
        }
        catch (CryptographicException)
        {
            // Malformed / non-PKCS#7 payload: treat as no timestamp.
            return false;
        }
        return false;
    }
}
