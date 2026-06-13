using System.Text;
using System.Text.Json;
using Xunit;

namespace Kseal.Desktop.Tests;

public class ConnectTrustSessionClientTests
{
    private static readonly TrustSessionConfig Config =
        new(new Uri("https://trust.example.com/"), "tenant-1", "app-1", Platform.Unspecified);

    [Fact]
    public void GetNonceDecodesBase64()
    {
        byte[] expected = [1, 2, 3, 4, 5];
        var transport = new FakeHttpTransport().On("GetNonce",
            FakeHttpTransport.Json($$"""{"nonce":"{{Convert.ToBase64String(expected)}}"}"""));
        var client = new ConnectTrustSessionClient(Config, transport);

        Assert.Equal(expected, client.GetNonce());
    }

    [Fact]
    public void GetNonceTargetsTrustServicePath()
    {
        var transport = new FakeHttpTransport().On("GetNonce",
            FakeHttpTransport.Json($$"""{"nonce":"{{Convert.ToBase64String(new byte[] { 9 })}}"}"""));
        new ConnectTrustSessionClient(Config, transport).GetNonce();

        Assert.EndsWith("kseal.v1.TrustService/GetNonce", transport.Requests[0].Url.AbsolutePath);
        Assert.Equal("application/json", transport.Requests[0].Headers["Content-Type"]);
        Assert.Equal("1", transport.Requests[0].Headers["Connect-Protocol-Version"]);
    }

    [Fact]
    public void GetNonceThrowsOnMissingNonce()
    {
        var transport = new FakeHttpTransport().On("GetNonce", FakeHttpTransport.Json("{}"));
        var client = new ConnectTrustSessionClient(Config, transport);
        Assert.Throws<TrustSessionException>(() => client.GetNonce());
    }

    [Fact]
    public void GetNonceThrowsOnHttpError()
    {
        var transport = new FakeHttpTransport().On("GetNonce",
            new HttpTransportResponse(500, Encoding.UTF8.GetBytes("""{"code":"internal","message":"boom"}""")));
        var client = new ConnectTrustSessionClient(Config, transport);
        var ex = Assert.Throws<TrustSessionException>(() => client.GetNonce());
        Assert.Contains("internal", ex.Message);
    }

    [Fact]
    public void VerifyAttestationParsesAcceptedSession()
    {
        string json = """
        {
          "accepted": true,
          "signedToken": "AAEC",
          "trustToken": {
            "tokenId": "tok-123",
            "expiresAt": "1700000000",
            "riskLevel": "TRUST_LEVEL_TRUSTED",
            "capabilityScope": ["read", "write"]
          }
        }
        """;
        var transport = new FakeHttpTransport().On("VerifyAttestation", FakeHttpTransport.Json(json));
        var client = new ConnectTrustSessionClient(Config, transport);

        var session = client.VerifyAttestation([1, 2, 3], 0b110, "build", "policy", "instance", [9, 9]);

        Assert.True(session.Accepted);
        Assert.Equal("tok-123", session.TokenId);
        Assert.Equal(new byte[] { 0, 1, 2 }, session.SignedToken);
        Assert.Equal(1700000000L, session.ExpiresAt);
        Assert.Equal(TrustLevel.Trusted, session.RiskLevel);
        Assert.Equal(["read", "write"], session.CapabilityScopes);
    }

    [Fact]
    public void VerifyAttestationSendsRiskBitsetAsStringAndBase64Fields()
    {
        var transport = new FakeHttpTransport().On("VerifyAttestation",
            FakeHttpTransport.Json("""{"accepted":false,"rejectionReason":"nope"}"""));
        var client = new ConnectTrustSessionClient(Config, transport);

        var session = client.VerifyAttestation([0xAA], riskBitset: 192, "b", "p", "inst", [0xBB]);

        Assert.False(session.Accepted);
        Assert.Equal("nope", session.RejectionReason);

        using var doc = JsonDocument.Parse(transport.Requests[0].Body);
        var root = doc.RootElement;
        Assert.Equal("192", root.GetProperty("riskBitset").GetString()); // int64 as string
        Assert.Equal(Convert.ToBase64String(new byte[] { 0xAA }), root.GetProperty("nonce").GetString());
        Assert.Equal(Convert.ToBase64String(new byte[] { 0xBB }), root.GetProperty("platformAttestationToken").GetString());
        Assert.Equal("PLATFORM_UNSPECIFIED", root.GetProperty("platform").GetString());
    }

    [Fact]
    public void VerifyAttestationOmitsAttestationTokenWhenEmpty()
    {
        var transport = new FakeHttpTransport().On("VerifyAttestation",
            FakeHttpTransport.Json("""{"accepted":true,"trustToken":{"tokenId":"t"}}"""));
        var client = new ConnectTrustSessionClient(Config, transport);

        client.VerifyAttestation([1], 0, "b", "p", "inst", []);

        using var doc = JsonDocument.Parse(transport.Requests[0].Body);
        Assert.False(doc.RootElement.TryGetProperty("platformAttestationToken", out _));
    }

    [Fact]
    public void ValidateRequestProofForwardsBytesAndDecodesDecision()
    {
        // RequestProofResult { decision = STEP_UP (2), reason = "mfa" }
        byte[] result = [0x08, 0x02, 0x12, 0x03, .. "mfa"u8];
        var transport = new FakeHttpTransport().On("ValidateRequestProof",
            new HttpTransportResponse(200, result));
        var client = new ConnectTrustSessionClient(Config, transport);

        byte[] proofBytes = [0xDE, 0xAD, 0xBE, 0xEF];
        var proof = new RequestProof("tok", [1], [2], 1, proofBytes);
        var decision = client.ValidateRequestProof(proof);

        Assert.Equal(TrustDecision.StepUp, decision.Decision);
        Assert.Equal("mfa", decision.Reason);
        Assert.Equal(proofBytes, transport.Requests[0].Body); // forwarded verbatim
        Assert.Equal("application/proto", transport.Requests[0].Headers["Content-Type"]);
    }

    [Fact]
    public void ValidateRequestProofThrowsOnHttpError()
    {
        var transport = new FakeHttpTransport().On("ValidateRequestProof", new HttpTransportResponse(403, []));
        var client = new ConnectTrustSessionClient(Config, transport);
        var proof = new RequestProof("tok", [1], [2], 1, [0]);
        Assert.Throws<TrustSessionException>(() => client.ValidateRequestProof(proof));
    }
}
