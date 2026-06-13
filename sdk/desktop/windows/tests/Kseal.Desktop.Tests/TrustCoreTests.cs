using Xunit;

namespace Kseal.Desktop.Tests;

/// <summary>
/// Exercises the real Rust core over the C ABI (no faked core). Requires the
/// shared library on the load path — KSEAL_FFI_LIBRARY points at it (see
/// scripts/build-rust-host.sh). These tests run the same code path production
/// uses.
/// </summary>
public class TrustCoreTests
{
    private static NativeTrustCore NewCore() =>
        NativeTrustCore.Create(new byte[32], new byte[32]);

    [Fact]
    public void VersionIsNonEmpty()
    {
        using var core = NewCore();
        Assert.False(string.IsNullOrEmpty(core.Version));
    }

    [Fact]
    public void NonceHasRequestedLength()
    {
        using var core = NewCore();
        Assert.Equal(16, core.GenerateNonce(16).Length);
        Assert.Equal(32, core.GenerateNonce(32).Length);
    }

    [Fact]
    public void NoncesAreUnique()
    {
        using var core = NewCore();
        byte[] a = core.GenerateNonce(16);
        byte[] b = core.GenerateNonce(16);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void CompressDecompressRoundTrips()
    {
        using var core = NewCore();
        byte[] data = System.Text.Encoding.UTF8.GetBytes(new string('k', 1024));
        byte[] compressed = core.Compress(data, 0);
        Assert.True(compressed.Length < data.Length);
        Assert.Equal(data, core.Decompress(compressed));
    }

    [Fact]
    public void CleanBitsScoreZero()
    {
        using var core = NewCore();
        var score = core.EvaluateRisk(0);
        Assert.Equal(0u, score.Score);
    }

    [Fact]
    public void RiskBitsProduceNonZeroScore()
    {
        using var core = NewCore();
        ulong bits = RiskSignals.Pack([RiskSignal.Tamper, RiskSignal.AppIntegrity]);
        Assert.True(core.EvaluateRisk(bits).Score > 0);
    }

    [Fact]
    public void TrustLevelUnspecifiedWithoutPolicy()
    {
        using var core = NewCore();
        ulong bits = RiskSignal.Tamper.Mask();
        Assert.Equal(TrustLevel.Unspecified, core.ComputeRiskLevel(bits));
    }

    [Fact]
    public void EvaluateRiskAndLevelAgreesWithSeparateCalls()
    {
        using var core = NewCore();
        ulong bits = RiskSignals.Pack([RiskSignal.Hooking, RiskSignal.Debugger]);
        var (score, level) = core.EvaluateRiskAndLevel(bits);
        Assert.Equal(core.EvaluateRisk(bits).Score, score.Score);
        Assert.Equal(core.ComputeRiskLevel(bits), level);
    }

    [Fact]
    public void CreateEventAndBatchProduceWire()
    {
        using var core = NewCore();
        byte[] evt = core.CreateEvent(
            EventType.RuntimeTamper, RiskSignal.Tamper.Mask(), Confidence.High,
            buildHash: "build-abc", policyHash: "policy-xyz", installKeyHash: "install-1",
            coarseTimeBucket: 0, country: null);
        Assert.NotEmpty(evt);

        byte[] wire = core.BatchAndCompress([evt]);
        Assert.NotEmpty(wire);
    }

    [Fact]
    public void RequestProofIsDeterministicAndSequenceSensitive()
    {
        using var core = NewCore();
        byte[] requestHash = System.Text.Encoding.UTF8.GetBytes("request-hash");
        byte[] nonce = core.GenerateNonce(16);

        byte[] proof1 = core.GenerateRequestProof("token-1", requestHash, nonce, 1);
        byte[] proof1Again = core.GenerateRequestProof("token-1", requestHash, nonce, 1);
        byte[] proof2 = core.GenerateRequestProof("token-1", requestHash, nonce, 2);

        Assert.Equal(proof1, proof1Again);   // deterministic for identical inputs
        Assert.NotEqual(proof1, proof2);      // sequence number changes the proof
    }

    [Fact]
    public void VerifyConfigSignatureRejectsGarbage()
    {
        Assert.False(NativeTrustCore.VerifyConfigSignature(new byte[8], new byte[64], new byte[32]));
    }

    [Fact]
    public void DisposeIsIdempotent()
    {
        var core = NewCore();
        core.Dispose();
        // A second dispose must be a no-op, not throw on the freed lock.
        var ex = Record.Exception(() => core.Dispose());
        Assert.Null(ex);
    }
}
