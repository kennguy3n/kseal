using System.Text;
using Xunit;

namespace Kseal.Desktop.Tests;

public class EnterprisePolicyTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"kseal-pol-{Guid.NewGuid():N}");

    public EnterprisePolicyTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void StrictBaselineRelaxesNothing()
    {
        var p = EnterprisePolicy.Strict;
        Assert.True(p.IsStrict);
        Assert.False(p.PermitDebugger);
        Assert.Empty(p.InjectionAllowlist);
        Assert.Equal(TelemetryVerbosity.Standard, p.TelemetryVerbosity);
        Assert.False(p.RequireHardwareBackedProofKey);
        Assert.False(p.AllowsModule(@"C:\anything.dll"));
    }

    [Fact]
    public void PartialJsonKeepsStrictDefaultsForMissingKeys()
    {
        var p = EnterprisePolicy.FromJson("""{ "permitDebugger": true }"""u8.ToArray());
        Assert.True(p.PermitDebugger);
        Assert.Empty(p.InjectionAllowlist);
        Assert.Equal(TelemetryVerbosity.Standard, p.TelemetryVerbosity);
        Assert.False(p.RequireHardwareBackedProofKey);
        Assert.False(p.IsStrict);
    }

    [Fact]
    public void FullJsonRoundTrip()
    {
        byte[] json = Encoding.UTF8.GetBytes("""
        {
          "permitDebugger": true,
          "injectionAllowlist": ["C:\\Program Files\\Acme\\plugin.dll", "C:\\agents\\"],
          "telemetryVerbosity": "minimal",
          "requireHardwareBackedProofKey": true
        }
        """);
        var p = EnterprisePolicy.FromJson(json);
        Assert.True(p.PermitDebugger);
        Assert.Equal(TelemetryVerbosity.Minimal, p.TelemetryVerbosity);
        Assert.True(p.RequireHardwareBackedProofKey);
        Assert.Equal(2, p.InjectionAllowlist.Count);
    }

    [Fact]
    public void MalformedJsonFailsSafeToStrict()
    {
        Assert.True(EnterprisePolicy.FromJson("not json"u8.ToArray()).IsStrict);
    }

    [Fact]
    public void AllowsModuleExactAndPrefixForBothSeparators()
    {
        var p = new EnterprisePolicy
        {
            InjectionAllowlist = [@"C:\Program Files\Acme\plugin.dll", @"C:\agents\", "/opt/agents/"],
        };
        Assert.True(p.AllowsModule(@"C:\Program Files\Acme\plugin.dll"));   // exact
        Assert.True(p.AllowsModule(@"C:\agents\telemetry.dll"));           // backslash prefix
        Assert.True(p.AllowsModule("/opt/agents/telemetry.so"));          // forward-slash prefix
        Assert.False(p.AllowsModule(@"C:\agents"));                        // prefix needs trailing sep
        Assert.False(p.AllowsModule(@"C:\Windows\evil.dll"));              // not listed
    }

    [Fact]
    public void AllowsModuleMatchesCasePerPlatform()
    {
        var p = new EnterprisePolicy
        {
            InjectionAllowlist = [@"C:\Program Files\Acme\plugin.dll", @"C:\agents\"],
        };
        // Windows module paths are case-insensitive; other hosts are case-sensitive.
        bool expected = OperatingSystem.IsWindows();
        Assert.Equal(expected, p.AllowsModule(@"c:\program files\acme\plugin.dll"));
        Assert.Equal(expected, p.AllowsModule(@"C:\AGENTS\telemetry.dll"));
    }

    [Fact]
    public void AllowsModuleRejectsParentTraversal()
    {
        var p = new EnterprisePolicy { InjectionAllowlist = [@"C:\agents\"] };
        // A '..' segment that escapes the allowlisted prefix must not be allowlisted.
        Assert.False(p.AllowsModule(@"C:\agents\..\evil.dll"));
        Assert.False(p.AllowsModule(@"C:\agents\sub\..\..\evil.dll"));
    }

    [Fact]
    public void FileProviderReadsPolicy()
    {
        string path = Path.Combine(_dir, "policy.json");
        File.WriteAllText(path, """{ "telemetryVerbosity": "verbose" }""");
        Assert.Equal(TelemetryVerbosity.Verbose, new FileEnterprisePolicyProvider(path).CurrentPolicy().TelemetryVerbosity);
    }

    [Fact]
    public void FileProviderFailsSafeOnMissingFile()
    {
        var provider = new FileEnterprisePolicyProvider(Path.Combine(_dir, "missing.json"));
        Assert.True(provider.CurrentPolicy().IsStrict);
    }

    [Fact]
    public void FileProviderFailsSafeOnMalformedFile()
    {
        string path = Path.Combine(_dir, "bad.json");
        File.WriteAllText(path, "not json");
        Assert.True(new FileEnterprisePolicyProvider(path).CurrentPolicy().IsStrict);
    }

    [Fact]
    public void StaticProvider()
    {
        var p = new EnterprisePolicy { PermitDebugger = true };
        Assert.Equal(p, new StaticEnterprisePolicyProvider(p).CurrentPolicy());
        Assert.True(new StaticEnterprisePolicyProvider().CurrentPolicy().IsStrict);
    }
}
