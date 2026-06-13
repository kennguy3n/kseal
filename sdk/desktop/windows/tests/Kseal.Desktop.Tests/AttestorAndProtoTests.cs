using System.Text;
using System.Text.Json;
using Xunit;

namespace Kseal.Desktop.Tests;

public class AttestorTests
{
    [Fact]
    public void SignedBinaryProducesSortedNonPiiToken()
    {
        var info = new AuthenticodeInfo(true, true, "CN=Contoso", "ABCD1234", TimestampValid: true);
        byte[] token = new LocalCodeIntegrityAttestor().AttestationToken(info);

        using var doc = JsonDocument.Parse(token);
        Assert.Equal("CN=Contoso", doc.RootElement.GetProperty("publisher").GetString());
        Assert.Equal("ABCD1234", doc.RootElement.GetProperty("thumbprint").GetString());
        Assert.Equal("1", doc.RootElement.GetProperty("timestamped").GetString());
    }

    [Fact]
    public void UnsignedBinaryProducesEmptyToken()
    {
        Assert.Empty(new LocalCodeIntegrityAttestor().AttestationToken(AuthenticodeInfo.Unsigned));
    }

    [Fact]
    public void InvalidSignatureProducesEmptyToken()
    {
        var info = new AuthenticodeInfo(true, false, "CN=X", "AB", false);
        Assert.Empty(new LocalCodeIntegrityAttestor().AttestationToken(info));
    }

    [Fact]
    public void TokenIsDeterministicAcrossCalls()
    {
        var info = new AuthenticodeInfo(true, true, "CN=Contoso", "ABCD", true);
        var attestor = new LocalCodeIntegrityAttestor();
        Assert.Equal(attestor.AttestationToken(info), attestor.AttestationToken(info));
    }
}

public class RequestProofResultProtoTests
{
    [Fact]
    public void DecodesAllowWithoutReason()
    {
        byte[] bytes = [0x08, 0x01]; // decision = ALLOW
        var decision = RequestProofResultProto.Decode(bytes);
        Assert.Equal(TrustDecision.Allow, decision.Decision);
        Assert.Equal("", decision.Reason);
    }

    [Fact]
    public void DecodesDenyWithReason()
    {
        byte[] bytes = [0x08, 0x03, 0x12, 0x04, .. "deny"u8];
        var decision = RequestProofResultProto.Decode(bytes);
        Assert.Equal(TrustDecision.Deny, decision.Decision);
        Assert.Equal("deny", decision.Reason);
    }

    [Fact]
    public void SkipsUnknownFields()
    {
        // field 5 (varint) unknown, then field 1 = ALLOW.
        byte[] bytes = [0x28, 0x7F, 0x08, 0x01];
        var decision = RequestProofResultProto.Decode(bytes);
        Assert.Equal(TrustDecision.Allow, decision.Decision);
    }

    [Fact]
    public void UnknownDecisionCodeMapsToUnspecified()
    {
        byte[] bytes = [0x08, 0x63]; // decision = 99
        Assert.Equal(TrustDecision.Unspecified, RequestProofResultProto.Decode(bytes).Decision);
    }

    [Fact]
    public void EmptyBytesDecodeToUnspecified()
    {
        Assert.Equal(TrustDecision.Unspecified, RequestProofResultProto.Decode([]).Decision);
    }

    [Fact]
    public void TruncatedVarintThrows()
    {
        Assert.Throws<TrustSessionException>(() => RequestProofResultProto.Decode([0x08, 0x80]));
    }

    [Fact]
    public void StringOverrunThrows()
    {
        // field 2, length 10, but only 2 bytes follow.
        Assert.Throws<TrustSessionException>(() => RequestProofResultProto.Decode([0x12, 0x0A, 0x61, 0x62]));
    }
}

public class RiskSignalTests
{
    [Fact]
    public void PackUnpackRoundTrips()
    {
        var signals = new HashSet<RiskSignal> { RiskSignal.Tamper, RiskSignal.Hooking, RiskSignal.AppIntegrity };
        ulong bits = RiskSignals.Pack(signals);
        Assert.Equal(signals, RiskSignals.Unpack(bits));
    }

    [Fact]
    public void BitIndicesMatchWireLayout()
    {
        Assert.Equal(1UL << 6, RiskSignal.Tamper.Mask());
        Assert.Equal(1UL << 7, RiskSignal.AppIntegrity.Mask());
        Assert.Equal(1UL << 5, RiskSignal.Hooking.Mask());
        Assert.Equal(1UL << 15, RiskSignal.Repackaged.Mask());
    }

    [Fact]
    public void EmptySetPacksToZero()
    {
        Assert.Equal(0UL, RiskSignals.Pack([]));
        Assert.Empty(RiskSignals.Unpack(0));
    }
}
