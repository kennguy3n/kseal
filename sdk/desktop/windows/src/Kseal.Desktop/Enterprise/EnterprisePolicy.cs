using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace Kseal.Desktop;

/// <summary>Telemetry detail the host is asked to honor.</summary>
public enum TelemetryVerbosity
{
    /// <summary>Only events that carry at least one risk signal are recorded.</summary>
    Minimal,

    /// <summary>Default: every event the host reports is recorded.</summary>
    Standard,

    /// <summary>Standard plus any additional diagnostics the host opts into.</summary>
    Verbose,
}

/// <summary>
/// MDM-friendly enterprise compatibility controls the desktop SDK reads from a
/// <b>managed configuration</b> (Windows: GPO/MDM-delivered registry policy under
/// <c>HKLM\SOFTWARE\Policies\Kseal\Desktop</c>, or a documented JSON drop file;
/// see <c>docs/desktop-sdk.md</c>).
///
/// Every default is <b>strict</b>: an unconfigured policy (<see cref="Strict"/>)
/// relaxes nothing and produces byte-for-byte the same behavior the SDK had
/// before this control existed. Controls are therefore opt-in, and the effective
/// policy is surfaced (<see cref="KsealDesktopClient.EnterprisePolicy"/>) so a
/// deployment can audit exactly what was relaxed.
/// </summary>
public sealed record EnterprisePolicy
{
    /// <summary>
    /// Suppress the (opt-in) debugger probe — for managed developer machines
    /// where debugging is legitimate. Strict default: false (no suppression).
    /// </summary>
    [JsonPropertyName("permitDebugger")]
    public bool PermitDebugger { get; init; }

    /// <summary>
    /// Module paths (exact match or directory prefix ending in <c>\</c> or
    /// <c>/</c>) that are legitimate plugins/agents and must not raise the
    /// injection signal.
    /// </summary>
    [JsonPropertyName("injectionAllowlist")]
    public IReadOnlyList<string> InjectionAllowlist { get; init; } = [];

    /// <summary>Telemetry detail the host should honor. Strict default: <see cref="TelemetryVerbosity.Standard"/>.</summary>
    [JsonPropertyName("telemetryVerbosity")]
    public TelemetryVerbosity TelemetryVerbosity { get; init; } = TelemetryVerbosity.Standard;

    /// <summary>
    /// When true, a request-proof key that is <b>not</b> hardware-backed raises
    /// the <see cref="RiskSignal.SecureHwMissing"/> signal (fail closed for a
    /// regulated tier). Strict default: false.
    /// </summary>
    [JsonPropertyName("requireHardwareBackedProofKey")]
    public bool RequireHardwareBackedProofKey { get; init; }

    /// <summary>The strict baseline: identical to the SDK's behavior with no managed configuration present.</summary>
    public static readonly EnterprisePolicy Strict = new();

    /// <summary>Whether this policy relaxes nothing relative to the strict baseline.</summary>
    public bool IsStrict =>
        !PermitDebugger
        && InjectionAllowlist.Count == 0
        && TelemetryVerbosity == TelemetryVerbosity.Standard
        && !RequireHardwareBackedProofKey;

    // Windows module paths are case-insensitive (NTFS/loader), so an MDM admin's
    // allowlist must match regardless of casing. Off Windows (the JSON-file
    // fallback path) filesystems are case-sensitive, so honor that.
    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    /// <summary>
    /// Whether a foreign module <paramref name="path"/> is allowlisted (exact
    /// match, or under an allowlist entry that names a directory prefix ending in
    /// a path separator). Path matching is case-insensitive on Windows.
    /// </summary>
    public bool AllowsModule(string path)
    {
        // Fail closed on a path that could escape an allowlisted prefix via a
        // parent-directory segment (e.g. C:\Acme\..\evil.dll): never allowlist it.
        if (HasParentTraversal(path)) return false;
        foreach (string entry in InjectionAllowlist)
        {
            if (string.IsNullOrEmpty(entry)) continue;
            if (entry.EndsWith('/') || entry.EndsWith('\\'))
            {
                if (path.StartsWith(entry, PathComparison)) return true;
            }
            else if (string.Equals(path, entry, PathComparison))
            {
                return true;
            }
        }
        return false;
    }

    // True if any path segment (split on either separator) is exactly "..".
    private static bool HasParentTraversal(string path)
    {
        foreach (string seg in path.Split('/', '\\'))
        {
            if (seg == "..") return true;
        }
        return false;
    }

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>
    /// Parses a policy from JSON, leaving any unspecified control at its strict
    /// default so a partial managed config only relaxes the keys it sets. Returns
    /// the strict baseline on malformed input (fail safe).
    /// </summary>
    public static EnterprisePolicy FromJson(byte[] json)
    {
        try
        {
            return JsonSerializer.Deserialize<EnterprisePolicy>(json, JsonOptions) ?? Strict;
        }
        catch (JsonException)
        {
            return Strict;
        }
    }
}

/// <summary>
/// Source of the effective <see cref="EnterprisePolicy"/>. Production reads the
/// OS-managed configuration; tests and hosts can inject a fixed policy.
/// </summary>
public interface IEnterprisePolicyProvider
{
    EnterprisePolicy CurrentPolicy();
}

/// <summary>
/// Always returns a fixed policy (default: strict). Used when a host supplies a
/// policy directly and as the safe fallback when no managed config is present.
/// </summary>
public sealed class StaticEnterprisePolicyProvider : IEnterprisePolicyProvider
{
    private readonly EnterprisePolicy _policy;
    public StaticEnterprisePolicyProvider(EnterprisePolicy? policy = null) => _policy = policy ?? EnterprisePolicy.Strict;
    public EnterprisePolicy CurrentPolicy() => _policy;
}

/// <summary>
/// Reads the policy from a JSON file (the documented MDM drop path and the
/// deterministic seam for tests). A missing or malformed file yields the strict
/// baseline (fail safe).
/// </summary>
public sealed class FileEnterprisePolicyProvider : IEnterprisePolicyProvider
{
    private readonly string _path;
    public FileEnterprisePolicyProvider(string path) => _path = path;

    public EnterprisePolicy CurrentPolicy()
    {
        try
        {
            if (!File.Exists(_path)) return EnterprisePolicy.Strict;
            return EnterprisePolicy.FromJson(File.ReadAllBytes(_path));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return EnterprisePolicy.Strict;
        }
    }
}

/// <summary>
/// Reads enterprise controls from <b>GPO/MDM-delivered machine policy</b> under
/// <c>HKLM\SOFTWARE\Policies\Kseal\Desktop</c> — the Windows analogue of macOS
/// managed preferences. Unset values keep the strict default.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryEnterprisePolicyProvider : IEnterprisePolicyProvider
{
    public const string DefaultSubKey = @"SOFTWARE\Policies\Kseal\Desktop";

    private readonly string _subKey;
    public RegistryEnterprisePolicyProvider(string subKey = DefaultSubKey) => _subKey = subKey;

    public EnterprisePolicy CurrentPolicy()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(_subKey);
            if (key is null) return EnterprisePolicy.Strict;

            var verbosity = TelemetryVerbosity.Standard;
            if (key.GetValue("TelemetryVerbosity") is string raw
                && Enum.TryParse(raw, ignoreCase: true, out TelemetryVerbosity parsed))
            {
                verbosity = parsed;
            }

            return new EnterprisePolicy
            {
                PermitDebugger = ReadFlag(key, "PermitDebugger"),
                RequireHardwareBackedProofKey = ReadFlag(key, "RequireHardwareBackedProofKey"),
                // REG_MULTI_SZ → string[]; absent/other types fall back to empty.
                InjectionAllowlist = key.GetValue("InjectionAllowlist") as string[] ?? [],
                TelemetryVerbosity = verbosity,
            };
        }
        // A restrictive registry ACL must never crash SDK init: fail safe to strict,
        // mirroring FileEnterprisePolicyProvider.
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            return EnterprisePolicy.Strict;
        }
    }

    // A REG_DWORD treated as a boolean flag (non-zero == true).
    private static bool ReadFlag(RegistryKey key, string name) => key.GetValue(name) is int i && i != 0;
}

/// <summary>Constructs the production enterprise-policy provider for the current platform.</summary>
internal static class EnterprisePolicyFactory
{
    public static IEnterprisePolicyProvider CreateDefault()
    {
        if (OperatingSystem.IsWindows()) return new RegistryEnterprisePolicyProvider();
        // Non-Windows host: read the documented JSON drop path if present, else strict.
        return new FileEnterprisePolicyProvider("/etc/kseal/desktop-enterprise-policy.json");
    }
}
