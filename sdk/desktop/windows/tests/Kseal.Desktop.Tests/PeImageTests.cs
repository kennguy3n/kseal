using System.Security.Cryptography;
using Kseal.Desktop.Pe;
using Xunit;

namespace Kseal.Desktop.Tests;

public class PeImageTests
{
    [Fact]
    public void ParsesValidImageWithSignatureAndSections()
    {
        byte[] text = [1, 2, 3, 4, 5, 6, 7, 8];
        var pe = PeImage.Parse(PeBuilder.Build([(".text", text), (".data", [9, 9])], certTableSize: 0x400));

        Assert.True(pe.IsValid);
        Assert.True(pe.HasEmbeddedSignature);
        Assert.Equal(0x400u, pe.CertificateTableSize);
        Assert.Equal(2, pe.Sections.Count);
        Assert.Contains(pe.Sections, s => s.Name == ".text");
        Assert.Contains(pe.Sections, s => s.Name == ".data");
    }

    [Fact]
    public void DetectsStrippedSignature()
    {
        var pe = PeImage.Parse(PeBuilder.BuildText([1, 2, 3], certTableSize: 0));
        Assert.True(pe.IsValid);
        Assert.False(pe.HasEmbeddedSignature);
    }

    [Fact]
    public void SectionSha256MatchesRawBytes()
    {
        byte[] text = [10, 20, 30, 40, 50];
        var pe = PeImage.Parse(PeBuilder.BuildText(text));
        string expected = Convert.ToHexString(SHA256.HashData(text)).ToLowerInvariant();
        Assert.Equal(expected, pe.SectionSha256(".text"));
    }

    [Fact]
    public void SectionSha256ChangesWhenSectionTampered()
    {
        var clean = PeImage.Parse(PeBuilder.BuildText([1, 1, 1, 1]));
        var tampered = PeImage.Parse(PeBuilder.BuildText([1, 1, 9, 1]));
        Assert.NotEqual(clean.SectionSha256(".text"), tampered.SectionSha256(".text"));
    }

    [Fact]
    public void SectionSha256NullForMissingSection()
    {
        var pe = PeImage.Parse(PeBuilder.BuildText([1, 2, 3]));
        Assert.Null(pe.SectionSha256(".rdata"));
    }

    [Fact]
    public void RejectsNonPeBytes()
    {
        Assert.False(PeImage.Parse([0, 1, 2, 3]).IsValid);
        Assert.False(PeImage.Parse(new byte[128]).IsValid); // zeroed: no MZ
    }

    [Fact]
    public void RejectsTruncatedImage()
    {
        byte[] full = PeBuilder.BuildText([1, 2, 3, 4]);
        byte[] truncated = full[..(full.Length - 3)]; // chop into the raw section data
        Assert.False(PeImage.Parse(truncated).IsValid);
    }

    [Fact]
    public void RejectsEmptyInput()
    {
        Assert.False(PeImage.Parse([]).IsValid);
    }
}
