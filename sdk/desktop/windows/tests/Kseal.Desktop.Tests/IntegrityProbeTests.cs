using System.Security.Cryptography;
using Kseal.Desktop.Pe;
using Xunit;

namespace Kseal.Desktop.Tests;

public class IntegrityProbeTests
{
    private static AuthenticodeInfo Valid(string publisher = "CN=Contoso", string thumbprint = "ABCD") =>
        new(IsSigned: true, SignatureValid: true, Publisher: publisher, CertificateThumbprint: thumbprint, TimestampValid: true);

    // --- AuthenticodeProbe ---

    [Fact]
    public void ValidSignatureCleanAppRaisesNothing()
    {
        var env = new FakeWindowsEnvironment { Authenticode = Valid() };
        var probe = new AuthenticodeProbe(env, new WindowsIntegrityPolicy());
        Assert.Empty(probe.Evaluate());
    }

    [Fact]
    public void UnsignedBinaryRaisesTamperAndIntegrity()
    {
        var env = new FakeWindowsEnvironment { Authenticode = AuthenticodeInfo.Unsigned };
        var probe = new AuthenticodeProbe(env, new WindowsIntegrityPolicy());
        var signals = probe.Evaluate();
        Assert.Contains(RiskSignal.Tamper, signals);
        Assert.Contains(RiskSignal.AppIntegrity, signals);
    }

    [Fact]
    public void InvalidSignatureRaisesTamper()
    {
        var env = new FakeWindowsEnvironment
        {
            Authenticode = Valid() with { SignatureValid = false },
        };
        var probe = new AuthenticodeProbe(env, new WindowsIntegrityPolicy());
        Assert.Contains(RiskSignal.Tamper, probe.Evaluate());
    }

    [Fact]
    public void WrongPublisherRaisesRepackaged()
    {
        var env = new FakeWindowsEnvironment { Authenticode = Valid(publisher: "CN=Evil") };
        var policy = new WindowsIntegrityPolicy { ExpectedPublisher = "CN=Contoso" };
        var signals = new AuthenticodeProbe(env, policy).Evaluate();
        Assert.Contains(RiskSignal.Repackaged, signals);
        Assert.Contains(RiskSignal.AppIntegrity, signals);
    }

    [Fact]
    public void WrongThumbprintRaisesRepackaged()
    {
        var env = new FakeWindowsEnvironment { Authenticode = Valid(thumbprint: "DEADBEEF") };
        var policy = new WindowsIntegrityPolicy { ExpectedCertificateThumbprint = "ABCD" };
        Assert.Contains(RiskSignal.Repackaged, new AuthenticodeProbe(env, policy).Evaluate());
    }

    [Fact]
    public void ThumbprintComparisonIsCaseInsensitive()
    {
        var env = new FakeWindowsEnvironment { Authenticode = Valid(thumbprint: "abcd") };
        var policy = new WindowsIntegrityPolicy { ExpectedCertificateThumbprint = "ABCD" };
        Assert.Empty(new AuthenticodeProbe(env, policy).Evaluate());
    }

    [Fact]
    public void MissingTimestampRaisesIntegrityWhenRequired()
    {
        var env = new FakeWindowsEnvironment { Authenticode = Valid() with { TimestampValid = false } };
        var policy = new WindowsIntegrityPolicy { RequireTimestamp = true };
        Assert.Contains(RiskSignal.AppIntegrity, new AuthenticodeProbe(env, policy).Evaluate());
    }

    [Fact]
    public void UnsignedAllowedWhenSignatureNotRequired()
    {
        var env = new FakeWindowsEnvironment { Authenticode = AuthenticodeInfo.Unsigned };
        var policy = new WindowsIntegrityPolicy { RequireValidSignature = false };
        Assert.Empty(new AuthenticodeProbe(env, policy).Evaluate());
    }

    // --- PeIntegrityProbe ---

    [Fact]
    public void ValidSignedPeRaisesNothing()
    {
        var env = new FakeWindowsEnvironment { Pe = PeImage.Parse(PeBuilder.BuildText([1, 2, 3, 4])) };
        Assert.Empty(new PeIntegrityProbe(env, new WindowsIntegrityPolicy()).Evaluate());
    }

    [Fact]
    public void MissingPeRaisesTamperAndIntegrity()
    {
        var env = new FakeWindowsEnvironment { Pe = null };
        var signals = new PeIntegrityProbe(env, new WindowsIntegrityPolicy()).Evaluate();
        Assert.Contains(RiskSignal.Tamper, signals);
        Assert.Contains(RiskSignal.AppIntegrity, signals);
    }

    [Fact]
    public void MalformedPeRaisesTamper()
    {
        var env = new FakeWindowsEnvironment { Pe = PeImage.Parse([0, 1, 2, 3]) };
        Assert.Contains(RiskSignal.Tamper, new PeIntegrityProbe(env, new WindowsIntegrityPolicy()).Evaluate());
    }

    [Fact]
    public void StrippedSignatureRaisesTamper()
    {
        var env = new FakeWindowsEnvironment { Pe = PeImage.Parse(PeBuilder.BuildText([1, 2, 3], certTableSize: 0)) };
        Assert.Contains(RiskSignal.Tamper, new PeIntegrityProbe(env, new WindowsIntegrityPolicy()).Evaluate());
    }

    [Fact]
    public void MatchingSectionHashRaisesNothing()
    {
        byte[] text = [5, 6, 7, 8, 9];
        string hash = Convert.ToHexString(SHA256.HashData(text)).ToLowerInvariant();
        var env = new FakeWindowsEnvironment { Pe = PeImage.Parse(PeBuilder.BuildText(text)) };
        var policy = new WindowsIntegrityPolicy { ExpectedSectionSha256 = hash };
        Assert.Empty(new PeIntegrityProbe(env, policy).Evaluate());
    }

    [Fact]
    public void TamperedSectionHashRaisesTamper()
    {
        byte[] baseline = [5, 6, 7, 8, 9];
        string hash = Convert.ToHexString(SHA256.HashData(baseline)).ToLowerInvariant();
        var env = new FakeWindowsEnvironment { Pe = PeImage.Parse(PeBuilder.BuildText([5, 6, 0, 8, 9])) };
        var policy = new WindowsIntegrityPolicy { ExpectedSectionSha256 = hash };
        Assert.Contains(RiskSignal.Tamper, new PeIntegrityProbe(env, policy).Evaluate());
    }

    // --- DllInjectionProbe ---

    [Fact]
    public void NoForeignModulesRaisesNothing()
    {
        Assert.Empty(new DllInjectionProbe(new FakeWindowsEnvironment()).Evaluate());
    }

    [Fact]
    public void ForeignModuleRaisesHooking()
    {
        var env = new FakeWindowsEnvironment();
        env.Foreign.Add(@"C:\Temp\inject.dll");
        Assert.Contains(RiskSignal.Hooking, new DllInjectionProbe(env).Evaluate());
    }

    // --- DebuggerProbe ---

    [Fact]
    public void DebuggerProbeDetectsAttachedDebugger()
    {
        var env = new FakeWindowsEnvironment { Debugger = true };
        Assert.Contains(RiskSignal.Debugger, new DebuggerProbe(env).Evaluate());
    }

    [Fact]
    public void DebuggerProbeQuietWhenNotAttached()
    {
        Assert.Empty(new DebuggerProbe(new FakeWindowsEnvironment { Debugger = false }).Evaluate());
    }
}
