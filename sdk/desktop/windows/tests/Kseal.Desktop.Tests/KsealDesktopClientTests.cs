using Kseal.Desktop.Pe;
using Xunit;

namespace Kseal.Desktop.Tests;

/// <summary>
/// End-to-end client behavior over the real Rust core (FFI) with faked OS
/// environment, attestor, and transport.
/// </summary>
public class KsealDesktopClientTests
{
    private sealed class FixedClock(long millis) : IClock
    {
        public long NowMillis() => millis;
    }

    private static (KsealDesktopClient Client, FakeWindowsEnvironment Env, BufferingTelemetrySink Sink) NewClient(
        WindowsIntegrityPolicy? policy = null, KsealDesktopOptions? options = null)
    {
        var env = new FakeWindowsEnvironment
        {
            // A clean, validly signed app by default.
            Authenticode = new AuthenticodeInfo(true, true, "CN=Contoso", "ABCD", true),
            Pe = PeImage.Parse(PeBuilder.BuildText([1, 2, 3, 4])),
        };
        var core = NativeTrustCore.Create(new byte[32], new byte[32]);
        var sink = new BufferingTelemetrySink();
        var opts = options ?? new KsealDesktopOptions
        {
            BuildHash = "build-hash",
            IntegrityPolicy = policy ?? new WindowsIntegrityPolicy(),
        };
        var client = new KsealDesktopClient(
            core, env, opts, new FileConfigProvider(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString())),
            sink, new LocalCodeIntegrityAttestor(), installIdentityHash: "install-hash", new FixedClock(0));
        return (client, env, sink);
    }

    [Fact]
    public void CleanAppEvaluatesToNoSignals()
    {
        var (client, _, _) = NewClient();
        var assessment = client.EvaluateRisk();
        Assert.True(assessment.IsClean);
        Assert.Equal(0u, assessment.Score);
    }

    [Fact]
    public void TamperedAppRaisesSignalsAndScore()
    {
        var (client, env, _) = NewClient();
        env.Authenticode = AuthenticodeInfo.Unsigned;
        env.Pe = PeImage.Parse(PeBuilder.BuildText([1, 2, 3], certTableSize: 0));

        var assessment = client.EvaluateRisk();
        Assert.False(assessment.IsClean);
        Assert.Contains(RiskSignal.Tamper, assessment.Signals);
        Assert.Contains(RiskSignal.AppIntegrity, assessment.Signals);
        Assert.True(assessment.Score > 0);
    }

    [Fact]
    public void GetRequestProofThrowsWithoutTrustToken()
    {
        var (client, _, _) = NewClient();
        Assert.Throws<TrustCoreException>(() => client.GetRequestProof([1, 2, 3]));
    }

    [Fact]
    public void GetRequestProofIncrementsSequence()
    {
        var (client, _, _) = NewClient();
        client.SetTrustToken("tok-1");
        var p1 = client.GetRequestProof([1, 2, 3]);
        var p2 = client.GetRequestProof([1, 2, 3]);
        Assert.Equal(1, p1.Sequence);
        Assert.Equal(2, p2.Sequence);
        Assert.NotEmpty(p1.ProofBytes);
        Assert.NotEqual(p1.ProofBytes, p2.ProofBytes);
    }

    [Fact]
    public void EstablishTrustSessionStoresTokenAndDrivesFlow()
    {
        var (client, _, _) = NewClient();
        var transport = new FakeHttpTransport()
            .On("GetNonce", FakeHttpTransport.Json($$"""{"nonce":"{{Convert.ToBase64String(new byte[] { 1, 2, 3, 4 })}}"}"""))
            .On("VerifyAttestation", FakeHttpTransport.Json("""{"accepted":true,"trustToken":{"tokenId":"tok-xyz"}}"""));
        var sessionClient = new ConnectTrustSessionClient(
            new TrustSessionConfig(new Uri("https://t.example.com/"), "tenant", "app"), transport);

        var session = client.EstablishTrustSession(sessionClient);

        Assert.True(session.Accepted);
        Assert.Equal("tok-xyz", session.TokenId);
        // Token stored: request proofs now succeed.
        Assert.NotNull(client.GetRequestProof([9, 9]));
    }

    [Fact]
    public void AuthorizeRequestReturnsServerDecision()
    {
        var (client, _, _) = NewClient();
        client.SetTrustToken("tok-1");
        var transport = new FakeHttpTransport().On("ValidateRequestProof",
            new HttpTransportResponse(200, [0x08, 0x01])); // ALLOW
        var sessionClient = new ConnectTrustSessionClient(
            new TrustSessionConfig(new Uri("https://t.example.com/"), "tenant", "app"), transport);

        var decision = client.AuthorizeRequest([1, 2, 3], sessionClient);
        Assert.Equal(TrustDecision.Allow, decision.Decision);
    }

    [Fact]
    public void ReportEventBuffersUntilBatchThenFlushes()
    {
        var (client, _, sink) = NewClient(options: new KsealDesktopOptions { BuildHash = "b", MaxBatchEvents = 3 });
        client.ReportEvent(EventType.PolicyDecision);
        client.ReportEvent(EventType.PolicyDecision);
        Assert.Empty(sink.Drain()); // not yet flushed

        client.ReportEvent(EventType.PolicyDecision); // hits batch size
        Assert.Single(sink.Drain());
    }

    [Fact]
    public void FlushTelemetrySendsPendingEvents()
    {
        var (client, _, sink) = NewClient(options: new KsealDesktopOptions { BuildHash = "b", MaxBatchEvents = 100 });
        client.ReportEvent(EventType.RuntimeTamper);
        client.FlushTelemetry();
        Assert.Single(sink.Drain());
    }

    [Fact]
    public void FlushTelemetryNoopWhenEmpty()
    {
        var (client, _, sink) = NewClient();
        client.FlushTelemetry();
        Assert.Empty(sink.Drain());
    }

    [Fact]
    public void ReportPinningFailureEmitsImmediately()
    {
        var (client, _, sink) = NewClient();
        client.ReportPinningFailure();
        Assert.Single(sink.Drain());
    }

    [Fact]
    public void DebuggerProbeOptInChangesEvaluation()
    {
        var (client, env, _) = NewClient(options: new KsealDesktopOptions
        {
            BuildHash = "b",
            EnabledProbes = new HashSet<string> { "windows.debugger" },
        });
        env.Debugger = true;
        Assert.Contains(RiskSignal.Debugger, client.EvaluateRisk().Signals);
    }

    [Fact]
    public void DebuggerNotInDefaultProbeSet()
    {
        var (client, env, _) = NewClient();
        env.Debugger = true;
        Assert.DoesNotContain(RiskSignal.Debugger, client.EvaluateRisk().Signals);
    }
}
