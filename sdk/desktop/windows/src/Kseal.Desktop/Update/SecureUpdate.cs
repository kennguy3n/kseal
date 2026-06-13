using System.Text.Json;
using System.Text.Json.Serialization;

namespace Kseal.Desktop;

/// <summary>
/// A dotted numeric version (<c>FileVersion</c>-style) with a total order that
/// compares component-by-component numerically, so <c>1.10.0</c> correctly
/// outranks <c>1.9.0</c>. Non-numeric components compare as 0; a missing trailing
/// component is treated as 0 so <c>1.2</c> == <c>1.2.0</c>.
/// </summary>
public readonly struct UpdateVersion : IComparable<UpdateVersion>, IEquatable<UpdateVersion>
{
    public string Raw { get; }
    private readonly int[]? _components;

    // Never null even for default(UpdateVersion), which bypasses the constructor.
    private int[] Components => _components ?? [];

    public UpdateVersion(string raw)
    {
        Raw = raw ?? "";
        _components = Raw.Split('.')
            .Select(part => int.TryParse(new string(part.TakeWhile(char.IsDigit).ToArray()), out int n) ? n : 0)
            .ToArray();
    }

    public int CompareTo(UpdateVersion other)
    {
        int[] a = Components, b = other.Components;
        int count = Math.Max(a.Length, b.Length);
        for (int i = 0; i < count; i++)
        {
            int l = i < a.Length ? a[i] : 0;   // missing trailing component == 0
            int r = i < b.Length ? b[i] : 0;
            if (l != r) return l.CompareTo(r);
        }
        return 0;
    }

    public bool Equals(UpdateVersion other) => CompareTo(other) == 0;
    public override bool Equals(object? obj) => obj is UpdateVersion v && Equals(v);

    // Consistent with Equals: ignore trailing-zero components so 2.0 and 2.0.0 hash equally.
    public override int GetHashCode()
    {
        int[] c = Components;
        int len = c.Length;
        while (len > 0 && c[len - 1] == 0) len--;
        var hash = new HashCode();
        for (int i = 0; i < len; i++) hash.Add(c[i]);
        return hash.ToHashCode();
    }

    public override string ToString() => Raw;

    public static bool operator <(UpdateVersion a, UpdateVersion b) => a.CompareTo(b) < 0;
    public static bool operator >(UpdateVersion a, UpdateVersion b) => a.CompareTo(b) > 0;
    public static bool operator <=(UpdateVersion a, UpdateVersion b) => a.CompareTo(b) <= 0;
    public static bool operator >=(UpdateVersion a, UpdateVersion b) => a.CompareTo(b) >= 0;
    public static bool operator ==(UpdateVersion a, UpdateVersion b) => a.CompareTo(b) == 0;
    public static bool operator !=(UpdateVersion a, UpdateVersion b) => a.CompareTo(b) != 0;
}

/// <summary>One entry in the signed update manifest.</summary>
public sealed record UpdateManifestItem
{
    [JsonPropertyName("version")]
    public string Version { get; init; } = "";

    [JsonPropertyName("shortVersion")]
    public string? ShortVersion { get; init; }

    [JsonPropertyName("url")]
    public string Url { get; init; } = "";

    [JsonPropertyName("length")]
    public long ContentLength { get; init; }

    /// <summary>Base64 Ed25519 signature over the <b>archive</b> bytes.</summary>
    [JsonPropertyName("edSignature")]
    public string EdSignature { get; init; } = "";

    [JsonPropertyName("minimumOsVersion")]
    public string? MinimumOsVersion { get; init; }

    internal UpdateVersion ParsedVersion => new(Version);
    internal UpdateVersion? ParsedMinimumOs => MinimumOsVersion is null ? null : new UpdateVersion(MinimumOsVersion);

    internal byte[]? DecodedSignature()
    {
        try { return Convert.FromBase64String(EdSignature); }
        catch (FormatException) { return null; }
    }
}

/// <summary>A parsed update manifest.</summary>
public sealed record UpdateManifest
{
    [JsonPropertyName("items")]
    public IReadOnlyList<UpdateManifestItem> Items { get; init; } = [];

    /// <summary>
    /// Parses the manifest JSON. Throws <see cref="SecureUpdateException"/> with
    /// <see cref="SecureUpdateError.MalformedFeed"/> on invalid input.
    /// </summary>
    public static UpdateManifest Parse(byte[] json)
    {
        try
        {
            return JsonSerializer.Deserialize<UpdateManifest>(json, JsonOptions) ?? new UpdateManifest();
        }
        catch (JsonException e)
        {
            throw new SecureUpdateException(SecureUpdateError.MalformedFeed, "malformed update manifest", e);
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
}

/// <summary>Why a secure-update check could not produce an applicable, verified update.</summary>
public enum SecureUpdateError
{
    /// <summary>The manifest could not be parsed.</summary>
    MalformedFeed,

    /// <summary>The downloaded archive's size did not match the manifest length.</summary>
    LengthMismatch,

    /// <summary>The EdDSA signature over the archive did not verify against the channel key.</summary>
    SignatureInvalid,

    /// <summary>Authenticode verification of the update payload was required by policy but failed.</summary>
    AuthenticodeInvalid,

    /// <summary>The channel public key is not a valid Ed25519 key (32 bytes).</summary>
    InvalidChannelKey,
}

/// <summary>
/// Raised when a secure-update check fails closed. Every failure mode is
/// deliberate: the channel never returns an update it could not fully verify.
/// </summary>
public sealed class SecureUpdateException : Exception
{
    public SecureUpdateError Error { get; }

    public SecureUpdateException(SecureUpdateError error, string message, Exception? inner = null)
        : base(message, inner) => Error = error;
}

/// <summary>An update whose archive bytes have passed every verification gate.</summary>
public sealed record VerifiedUpdate(UpdateManifestItem Item, byte[] Archive);

/// <summary>Outcome of a secure-update check.</summary>
public abstract record SecureUpdateResult
{
    private SecureUpdateResult() { }

    /// <summary>No applicable newer version is offered.</summary>
    public sealed record UpToDate : SecureUpdateResult;

    /// <summary>A newer version was offered and fully verified; safe to apply.</summary>
    public sealed record UpdateAvailable(VerifiedUpdate Update) : SecureUpdateResult;
}

// --- External boundaries (mocked) ---

/// <summary>
/// The external secure-update feed — the third-party boundary the engineering
/// rules say to mock. Production fronts an HTTPS manifest + CDN download; tests
/// inject a deterministic in-memory feed. <b>No network is performed by the SDK
/// itself</b>; the feed is the seam where the host's transport plugs in.
/// </summary>
public interface IUpdateFeed
{
    UpdateManifest FetchManifest();
    byte[] FetchArchive(UpdateManifestItem item);
}

/// <summary>
/// Confirms a downloaded update payload is Authenticode-signed by the expected
/// publisher — a thin seam over <c>WinVerifyTrust</c> so the Windows-only call is
/// mockable. Only consulted when the channel policy requires Authenticode.
/// </summary>
public interface IUpdatePackageVerifier
{
    bool VerifyAuthenticode(byte[] archive, UpdateManifestItem item);
}

/// <summary>Verifier that approves everything; the default when Authenticode is not required by policy.</summary>
public sealed class PermissivePackageVerifier : IUpdatePackageVerifier
{
    public bool VerifyAuthenticode(byte[] archive, UpdateManifestItem item) => true;
}

/// <summary>Verifies an Ed25519 signature over a message with a public key.</summary>
public delegate bool UpdateSignatureVerifier(byte[] message, byte[] signature, byte[] publicKey);

/// <summary>Configuration for a secure-update channel.</summary>
public sealed record UpdateChannelPolicy
{
    /// <summary>Ed25519 public key (32 bytes) the manifest EdDSA signatures must verify against.</summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>The currently running app version; only strictly-newer offers apply.</summary>
    public required UpdateVersion CurrentVersion { get; init; }

    /// <summary>The running OS version, used to honor an item's minimum-OS gate.</summary>
    public UpdateVersion? CurrentOsVersion { get; init; }

    /// <summary>
    /// When true, an offered update must additionally pass Authenticode
    /// verification of the payload (fail closed). Default false.
    /// </summary>
    public bool RequireAuthenticode { get; init; }
}

/// <summary>
/// Verifies the integrity/signature of a signed update channel <b>before</b>
/// anything is applied. The verification logic is real (Ed25519 EdDSA over the
/// downloaded archive — the same primitive the macOS appcast uses — plus length
/// and optional Authenticode checks); only the feed/Authenticode surface are
/// mocked. Fails closed on any signature/length/Authenticode failure.
/// </summary>
public sealed class SecureUpdateChannel
{
    private readonly UpdateChannelPolicy _policy;
    private readonly IUpdateFeed _feed;
    private readonly IUpdatePackageVerifier _packageVerifier;
    private readonly UpdateSignatureVerifier _verifySignature;

    public SecureUpdateChannel(
        UpdateChannelPolicy policy,
        IUpdateFeed feed,
        IUpdatePackageVerifier? packageVerifier = null,
        UpdateSignatureVerifier? verifySignature = null)
    {
        _policy = policy;
        _feed = feed;
        _packageVerifier = packageVerifier ?? new PermissivePackageVerifier();
        _verifySignature = verifySignature ?? NativeTrustCore.VerifyConfigSignature;
    }

    /// <summary>
    /// Selects the newest applicable item and fully verifies it. Returns
    /// <see cref="SecureUpdateResult.UpToDate"/> when nothing newer (or nothing
    /// the current OS can run) is offered; throws <see cref="SecureUpdateException"/>
    /// when an offered update fails any gate.
    /// </summary>
    public SecureUpdateResult CheckForUpdate()
    {
        if (_policy.PublicKey.Length != 32)
        {
            throw new SecureUpdateException(SecureUpdateError.InvalidChannelKey, "channel key must be 32 bytes");
        }

        UpdateManifest manifest = _feed.FetchManifest();
        UpdateManifestItem? item = manifest.Items
            .Where(i => i.ParsedVersion > _policy.CurrentVersion)
            .Where(CanRun)
            .Where(i => i.DecodedSignature() is not null)
            .OrderByDescending(i => i.ParsedVersion)
            .FirstOrDefault();

        if (item is null) return new SecureUpdateResult.UpToDate();

        byte[] archive = _feed.FetchArchive(item);
        if (archive.Length != item.ContentLength)
        {
            throw new SecureUpdateException(
                SecureUpdateError.LengthMismatch,
                $"declared length {item.ContentLength} != actual {archive.Length}");
        }

        byte[] signature = item.DecodedSignature()!;
        if (!_verifySignature(archive, signature, _policy.PublicKey))
        {
            throw new SecureUpdateException(SecureUpdateError.SignatureInvalid, "EdDSA signature did not verify");
        }

        if (_policy.RequireAuthenticode && !_packageVerifier.VerifyAuthenticode(archive, item))
        {
            throw new SecureUpdateException(SecureUpdateError.AuthenticodeInvalid, "Authenticode verification failed");
        }

        return new SecureUpdateResult.UpdateAvailable(new VerifiedUpdate(item, archive));
    }

    private bool CanRun(UpdateManifestItem item)
    {
        if (item.ParsedMinimumOs is not { } minimum) return true;
        if (_policy.CurrentOsVersion is not { } current) return true;
        return current >= minimum;
    }
}

/// <summary>
/// An <see cref="IUpdateFeed"/> backed by bytes already in memory — the
/// production default for hosts that fetch the manifest/archive with their own
/// transport and hand the bytes to the channel, and the deterministic feed used
/// by tests. Parsing the manifest and looking up the archive are real; no network
/// is performed.
/// </summary>
public sealed class InMemoryUpdateFeed : IUpdateFeed
{
    private readonly UpdateManifest _manifest;
    private readonly IReadOnlyDictionary<string, byte[]> _archives;

    public InMemoryUpdateFeed(byte[] manifestJson, IReadOnlyDictionary<string, byte[]> archives)
        : this(UpdateManifest.Parse(manifestJson), archives) { }

    public InMemoryUpdateFeed(UpdateManifest manifest, IReadOnlyDictionary<string, byte[]> archives)
    {
        _manifest = manifest;
        _archives = archives;
    }

    public UpdateManifest FetchManifest() => _manifest;

    // A missing archive is treated as a zero-length body so the channel's length
    // check fails closed rather than the feed inventing bytes.
    public byte[] FetchArchive(UpdateManifestItem item) =>
        _archives.TryGetValue(item.Url, out byte[]? bytes) ? bytes : [];
}
