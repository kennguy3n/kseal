using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Kseal.Desktop.Pe;
using Xunit;

namespace Kseal.Desktop.Tests;

public class AuthenticodeTimestampTests
{
    private static X509Certificate2 SelfSigned(string cn)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static byte[] SignedCmsBytes(bool countersigned)
    {
        using var signerCert = SelfSigned("kseal-signer");
        var cms = new SignedCms(new ContentInfo([1, 2, 3, 4]));
        cms.ComputeSignature(new CmsSigner(signerCert) { IncludeOption = X509IncludeOption.EndCertOnly });
        if (countersigned)
        {
            using var tsaCert = SelfSigned("kseal-tsa");
            cms.SignerInfos[0].ComputeCounterSignature(
                new CmsSigner(tsaCert) { IncludeOption = X509IncludeOption.EndCertOnly });
        }
        return cms.Encode();
    }

    [Fact]
    public void DetectsCounterSignatureTimestamp()
    {
        Assert.True(AuthenticodeTimestamp.HasTrustedTimestamp(SignedCmsBytes(countersigned: true)));
    }

    [Fact]
    public void PlainSignatureHasNoTimestamp()
    {
        // A valid (non-expired) signature without a countersignature must NOT be
        // reported as timestamped — the old cert-expiry heuristic got this wrong.
        Assert.False(AuthenticodeTimestamp.HasTrustedTimestamp(SignedCmsBytes(countersigned: false)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[0])]
    public void EmptyOrNullIsNotTimestamped(byte[]? pkcs7)
    {
        Assert.False(AuthenticodeTimestamp.HasTrustedTimestamp(pkcs7));
    }

    [Fact]
    public void GarbageBytesAreNotTimestamped()
    {
        Assert.False(AuthenticodeTimestamp.HasTrustedTimestamp([0xDE, 0xAD, 0xBE, 0xEF]));
    }

    [Fact]
    public void RoundTripsEmbeddedPkcs7ThroughPeImage()
    {
        byte[] pkcs7 = SignedCmsBytes(countersigned: true);
        var pe = PeImage.Parse(PeBuilder.BuildWithCertificate(pkcs7));

        Assert.True(pe.IsValid);
        Assert.True(pe.HasEmbeddedSignature);
        byte[]? extracted = pe.EmbeddedPkcs7();
        Assert.NotNull(extracted);
        Assert.Equal(pkcs7, extracted);
        Assert.True(AuthenticodeTimestamp.HasTrustedTimestamp(extracted));
    }

    [Fact]
    public void NonPkcs7CertificateTypeYieldsNoPkcs7()
    {
        // wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA (e.g. 0x0001) is ignored.
        var pe = PeImage.Parse(PeBuilder.BuildWithCertificate([1, 2, 3, 4], certType: 0x0001));
        Assert.Null(pe.EmbeddedPkcs7());
    }

    [Fact]
    public void UnsignedImageHasNoPkcs7()
    {
        var pe = PeImage.Parse(PeBuilder.BuildText([1, 2, 3], certTableSize: 0));
        Assert.Null(pe.EmbeddedPkcs7());
    }
}
