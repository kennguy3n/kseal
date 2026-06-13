using System.Text;
using Xunit;

namespace Kseal.Desktop.Tests;

/// <summary>
/// Exercises the secure-update verification against the <b>real</b> Ed25519
/// verifier in the Rust core over the C ABI, using fixed test vectors signed by
/// a known Ed25519 key (the external feed/Authenticode surface is mocked).
/// </summary>
public class SecureUpdateTests
{
    // Ed25519 public key (32 raw bytes) matching the signatures below.
    private static readonly byte[] PublicKey =
    [
        60, 237, 247, 255, 72, 221, 244, 209, 215, 7, 12, 78, 108, 106, 164, 173,
        35, 191, 29, 238, 148, 173, 81, 111, 122, 123, 212, 211, 227, 211, 34, 244,
    ];

    private static readonly byte[] Archive2 = Encoding.UTF8.GetBytes("kseal-update-archive-v2.0.0-payload");        // len 35
    private static readonly byte[] Archive3 = Encoding.UTF8.GetBytes("kseal-update-archive-v3.0.0-payload-bigger"); // len 42
    private const string Sig2 = "d0e4iyWmsU8YBw+xumDMA7E18h1IdiY4up3F211Va6XXINVNVDlZrZxwPh8fSKrSM3uv6KitoRY/SrMf3/LxDA==";
    private const string Sig3 = "7K34Kguf2PymzBV4hOOgiMuTPqVbg4orirvI2f/qmP10FSa4JJNGWOB+/EvTuSFMOPgMnFX0IO2lN8yQow5BAA==";
    private const string Url2 = "https://updates.example/app-2.0.0.zip";
    private const string Url3 = "https://updates.example/app-3.0.0.zip";

    private static byte[] ManifestJson(int length2 = 35, int length3 = 42) => Encoding.UTF8.GetBytes($$"""
    {
      "items": [
        { "version": "2.0.0", "url": "{{Url2}}", "length": {{length2}}, "edSignature": "{{Sig2}}" },
        { "version": "3.0.0", "url": "{{Url3}}", "length": {{length3}}, "edSignature": "{{Sig3}}", "minimumOsVersion": "10.0.22000" }
      ]
    }
    """);

    private static InMemoryUpdateFeed Feed(int length2 = 35, int length3 = 42, bool tamper = false)
    {
        byte[] a3 = tamper ? Encoding.UTF8.GetBytes("tampered-archive-bytes-tampered-archive-by") : Archive3;
        return new InMemoryUpdateFeed(
            ManifestJson(length2, length3),
            new Dictionary<string, byte[]> { [Url2] = Archive2, [Url3] = a3 });
    }

    private static UpdateChannelPolicy Policy(
        string current, string? os = "10.0.22631", bool requireAuthenticode = false) => new()
    {
        PublicKey = PublicKey,
        CurrentVersion = new UpdateVersion(current),
        CurrentOsVersion = os is null ? null : new UpdateVersion(os),
        RequireAuthenticode = requireAuthenticode,
    };

    [Fact]
    public void VersionOrdering()
    {
        Assert.True(new UpdateVersion("1.10.0") > new UpdateVersion("1.9.0"));
        Assert.True(new UpdateVersion("2.0") == new UpdateVersion("2.0.0"));
        Assert.True(new UpdateVersion("3.0.1") > new UpdateVersion("3.0.0"));
        Assert.False(new UpdateVersion("1.0.0") > new UpdateVersion("1.0.0"));

        // Equal versions must hash equally; default must be usable (no NPE).
        Assert.Equal(new UpdateVersion("2.0").GetHashCode(), new UpdateVersion("2.0.0").GetHashCode());
        Assert.Equal(0, default(UpdateVersion).CompareTo(new UpdateVersion("0.0")));
    }

    [Fact]
    public void ParsesWellFormedManifest()
    {
        var manifest = UpdateManifest.Parse(ManifestJson());
        Assert.Equal(2, manifest.Items.Count);
        Assert.Equal("3.0.0", manifest.Items[1].Version);
        Assert.Equal(35, manifest.Items[0].ContentLength);
    }

    [Fact]
    public void MalformedManifestThrows()
    {
        var ex = Assert.Throws<SecureUpdateException>(() => UpdateManifest.Parse("{ not json"u8.ToArray()));
        Assert.Equal(SecureUpdateError.MalformedFeed, ex.Error);
    }

    [Fact]
    public void SelectsNewestAndVerifiesValidSignature()
    {
        var channel = new SecureUpdateChannel(Policy("1.0.0"), Feed());
        var available = Assert.IsType<SecureUpdateResult.UpdateAvailable>(channel.CheckForUpdate());
        Assert.Equal("3.0.0", available.Update.Item.Version);
        Assert.Equal(Archive3, available.Update.Archive);
    }

    [Fact]
    public void MinimumOsVersionGatesNewerItem()
    {
        // OS too old for v3 → falls back to verifying v2 (no OS gate).
        var channel = new SecureUpdateChannel(Policy("1.0.0", os: "10.0.19041"), Feed());
        var available = Assert.IsType<SecureUpdateResult.UpdateAvailable>(channel.CheckForUpdate());
        Assert.Equal("2.0.0", available.Update.Item.Version);
    }

    [Fact]
    public void UpToDateWhenCurrentIsNewest()
    {
        var channel = new SecureUpdateChannel(Policy("3.0.0"), Feed());
        Assert.IsType<SecureUpdateResult.UpToDate>(channel.CheckForUpdate());
    }

    [Fact]
    public void TamperedArchiveFailsClosed()
    {
        var channel = new SecureUpdateChannel(Policy("1.0.0"), Feed(tamper: true));
        var ex = Assert.Throws<SecureUpdateException>(() => channel.CheckForUpdate());
        Assert.Equal(SecureUpdateError.SignatureInvalid, ex.Error);
    }

    [Fact]
    public void LengthMismatchFailsClosed()
    {
        var channel = new SecureUpdateChannel(Policy("1.0.0"), Feed(length3: 999));
        var ex = Assert.Throws<SecureUpdateException>(() => channel.CheckForUpdate());
        Assert.Equal(SecureUpdateError.LengthMismatch, ex.Error);
    }

    [Fact]
    public void AuthenticodeRequiredAndMissingFailsClosed()
    {
        var channel = new SecureUpdateChannel(
            Policy("1.0.0", requireAuthenticode: true), Feed(), new DenyPackageVerifier());
        var ex = Assert.Throws<SecureUpdateException>(() => channel.CheckForUpdate());
        Assert.Equal(SecureUpdateError.AuthenticodeInvalid, ex.Error);
    }

    [Fact]
    public void AuthenticodeRequiredAndPresentSucceeds()
    {
        var channel = new SecureUpdateChannel(
            Policy("1.0.0", requireAuthenticode: true), Feed(), new PermissivePackageVerifier());
        Assert.IsType<SecureUpdateResult.UpdateAvailable>(channel.CheckForUpdate());
    }

    [Fact]
    public void InvalidChannelKeyFailsClosed()
    {
        var policy = new UpdateChannelPolicy { PublicKey = new byte[16], CurrentVersion = new UpdateVersion("1.0.0") };
        var ex = Assert.Throws<SecureUpdateException>(() => new SecureUpdateChannel(policy, Feed()).CheckForUpdate());
        Assert.Equal(SecureUpdateError.InvalidChannelKey, ex.Error);
    }

    [Fact]
    public void WrongChannelKeyRejectsValidlySignedArchive()
    {
        var policy = new UpdateChannelPolicy
        {
            PublicKey = Enumerable.Repeat((byte)9, 32).ToArray(),
            CurrentVersion = new UpdateVersion("1.0.0"),
        };
        var ex = Assert.Throws<SecureUpdateException>(() => new SecureUpdateChannel(policy, Feed()).CheckForUpdate());
        Assert.Equal(SecureUpdateError.SignatureInvalid, ex.Error);
    }

    private sealed class DenyPackageVerifier : IUpdatePackageVerifier
    {
        public bool VerifyAuthenticode(byte[] archive, UpdateManifestItem item) => false;
    }
}
