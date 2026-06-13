using Kseal.Desktop.Pe;
using Xunit;

namespace Kseal.Desktop.Tests;

/// <summary>
/// Verifies the effect of enterprise controls on the live client against the
/// real Rust core with a faked OS environment.
/// </summary>
public class EnterprisePolicyWiringTests
{
    private sealed class FixedClock(long millis) : IClock
    {
        public long NowMillis() => millis;
    }

    private static (KsealDesktopClient Client, FakeWindowsEnvironment Env, BufferingTelemetrySink Sink) NewClient(
        EnterprisePolicy enterprise,
        bool proofKeyIsHardwareBacked = false,
        IReadOnlySet<string>? enabledProbes = null)
    {
        var env = new FakeWindowsEnvironment
        {
            Authenticode = new AuthenticodeInfo(true, true, "CN=Contoso", "ABCD", true),
            Pe = PeImage.Parse(PeBuilder.BuildText([1, 2, 3, 4])),
        };
        var core = NativeTrustCore.Create(new byte[32], new byte[32]);
        var sink = new BufferingTelemetrySink();
        var opts = new KsealDesktopOptions { BuildHash = "build-hash", EnabledProbes = enabledProbes };
        var client = new KsealDesktopClient(
            core, env, opts, new FileConfigProvider(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString())),
            sink, new LocalCodeIntegrityAttestor(), "install-hash", new FixedClock(0),
            proofKeyIsHardwareBacked, enterprise);
        return (client, env, sink);
    }

    [Fact]
    public void StrictPolicyFlagsForeignModule()
    {
        var (client, env, _) = NewClient(EnterprisePolicy.Strict);
        env.Foreign.Add(@"C:\temp\inject.dll");
        Assert.Contains(RiskSignal.Hooking, client.EvaluateRisk().Signals);
    }

    [Fact]
    public void InjectionAllowlistSuppressesSanctionedModule()
    {
        var policy = new EnterprisePolicy { InjectionAllowlist = [@"C:\Program Files\Acme\"] };
        var (client, env, _) = NewClient(policy);
        env.Foreign.Add(@"C:\Program Files\Acme\plugin.dll");
        Assert.DoesNotContain(RiskSignal.Hooking, client.EvaluateRisk().Signals);
    }

    [Fact]
    public void AllowlistStillFlagsNonListedModule()
    {
        var policy = new EnterprisePolicy { InjectionAllowlist = [@"C:\Program Files\Acme\"] };
        var (client, env, _) = NewClient(policy);
        env.Foreign.Add(@"C:\Program Files\Acme\plugin.dll");
        env.Foreign.Add(@"C:\temp\evil.dll");
        Assert.Contains(RiskSignal.Hooking, client.EvaluateRisk().Signals);
    }

    [Fact]
    public void PermitDebuggerDropsDebuggerProbeEvenWhenEnabled()
    {
        var enabled = new HashSet<string> { "windows.debugger" };

        var (strict, env1, _) = NewClient(EnterprisePolicy.Strict, enabledProbes: enabled);
        env1.Debugger = true;
        Assert.Contains(RiskSignal.Debugger, strict.EvaluateRisk().Signals);

        var (permitted, env2, _) = NewClient(
            new EnterprisePolicy { PermitDebugger = true }, enabledProbes: enabled);
        env2.Debugger = true;
        Assert.DoesNotContain(RiskSignal.Debugger, permitted.EvaluateRisk().Signals);
    }

    [Fact]
    public void RequireHardwareBackedProofKeyRaisesSecureHwMissing()
    {
        var policy = new EnterprisePolicy { RequireHardwareBackedProofKey = true };

        var (missing, _, _) = NewClient(policy, proofKeyIsHardwareBacked: false);
        Assert.Contains(RiskSignal.SecureHwMissing, missing.EvaluateRisk().Signals);

        var (present, _, _) = NewClient(policy, proofKeyIsHardwareBacked: true);
        Assert.DoesNotContain(RiskSignal.SecureHwMissing, present.EvaluateRisk().Signals);

        var (off, _, _) = NewClient(EnterprisePolicy.Strict, proofKeyIsHardwareBacked: false);
        Assert.DoesNotContain(RiskSignal.SecureHwMissing, off.EvaluateRisk().Signals);
    }

    [Fact]
    public void MinimalVerbosityDropsCleanEvents()
    {
        var (client, _, sink) = NewClient(new EnterprisePolicy { TelemetryVerbosity = TelemetryVerbosity.Minimal });
        client.ReportEvent(EventType.PolicyDecision);
        client.FlushTelemetry();
        Assert.Empty(sink.Drain());
    }

    [Fact]
    public void StandardVerbosityKeepsCleanEvents()
    {
        var (client, _, sink) = NewClient(EnterprisePolicy.Strict);
        client.ReportEvent(EventType.PolicyDecision);
        client.FlushTelemetry();
        Assert.NotEmpty(sink.Drain());
    }
}
