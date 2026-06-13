using System.Security.Cryptography;
using System.Text;

namespace Kseal.Desktop;

/// <summary>Monotonic clock seam (injectable for deterministic tests).</summary>
public interface IClock
{
    long NowMillis();
}

/// <summary>Wall-clock implementation.</summary>
public sealed class SystemClock : IClock
{
    public long NowMillis() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}

/// <summary>
/// Source of the tenant's signed config bytes. <see cref="CachedConfig"/> is
/// read at launch (no network); <see cref="FetchConfig"/> is invoked only on
/// demand and is where the host wires the signed-config CDN. The default never
/// performs network I/O — keeping launch network-free.
/// </summary>
public interface IConfigProvider
{
    byte[]? CachedConfig();
    byte[]? FetchConfig();
    void Persist(byte[] config);
}

/// <summary>Default file-backed config cache under the app's private storage.</summary>
public sealed class FileConfigProvider : IConfigProvider
{
    private readonly string _path;

    public FileConfigProvider(string directory)
    {
        string dir = Path.Combine(directory, "kseal");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "config.bin");
    }

    public byte[]? CachedConfig() => File.Exists(_path) ? File.ReadAllBytes(_path) : null;
    public byte[]? FetchConfig() => null;
    public void Persist(byte[] config) => File.WriteAllBytes(_path, config);
}

/// <summary>
/// Sink for compressed telemetry batches. Telemetry never leaves the device at
/// launch; the host wires a real uploader. The default buffers batches in memory
/// so nothing is sent until the host opts in (and tests can assert).
/// </summary>
public interface ITelemetrySink
{
    void Send(byte[] wirePayload);
}

/// <summary>In-memory sink: retains emitted batches; performs no network I/O.</summary>
public sealed class BufferingTelemetrySink : ITelemetrySink
{
    private readonly object _gate = new();
    private readonly List<byte[]> _batches = [];

    public void Send(byte[] wirePayload)
    {
        lock (_gate) { _batches.Add(wirePayload); }
    }

    public IReadOnlyList<byte[]> Drain()
    {
        lock (_gate)
        {
            var copy = _batches.ToArray();
            _batches.Clear();
            return copy;
        }
    }
}

/// <summary>Supplies the instance HMAC proof key binding request proofs to this install.</summary>
public interface IProofKeyProvider
{
    byte[] ProofKey();
}

/// <summary>
/// Persistent random proof key stored in the app's private storage.
///
/// Production should bind this to a TPM-backed key (CNG / <c>NCrypt</c> with a
/// non-exportable key in the Platform Crypto Provider) and have the core accept
/// a TPM-computed signature; the file-backed key here is the portable default
/// and the seam where that binding plugs in.
/// </summary>
public sealed class DefaultProofKeyProvider : IProofKeyProvider
{
    private readonly string _path;

    public DefaultProofKeyProvider(string directory)
    {
        string dir = Path.Combine(directory, "kseal");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "proof.key");
    }

    public byte[] ProofKey()
    {
        if (File.Exists(_path))
        {
            byte[] existing = File.ReadAllBytes(_path);
            if (existing.Length > 0) return existing;
        }
        byte[] key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(_path, key);
        return key;
    }
}

/// <summary>
/// Stable, non-PII install identity. Persists a random install id and derives a
/// tenant-scoped HMAC of it so the server can correlate an instance without ever
/// seeing the raw id (privacy guard: tenant-scoped hashes only).
/// </summary>
public sealed class InstallIdentity
{
    private readonly string _path;

    public InstallIdentity(string directory)
    {
        string dir = Path.Combine(directory, "kseal");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "install.id");
    }

    private byte[] InstallId()
    {
        if (File.Exists(_path))
        {
            byte[] existing = File.ReadAllBytes(_path);
            if (existing.Length > 0) return existing;
        }
        byte[] id = RandomNumberGenerator.GetBytes(16);
        File.WriteAllBytes(_path, id);
        return id;
    }

    /// <summary>
    /// Lowercase-hex tenant-scoped HMAC of the install id (never the raw id).
    /// Mirrors the other SDKs exactly —
    /// <c>HMAC-SHA256(key=installId, message="tenant\0app")</c> — so every
    /// platform shares one keyed construction (HMAC also avoids the
    /// length-extension weakness of a plain <c>SHA256(id || ctx)</c>).
    /// </summary>
    public string TenantScopedHash(string tenantId, string appId)
    {
        byte[] message = Encoding.UTF8.GetBytes($"{tenantId}\0{appId}");
        return HmacSha256Hex(InstallId(), message);
    }

    public static string HmacSha256Hex(byte[] key, byte[] message)
    {
        byte[] mac = HMACSHA256.HashData(key, message);
        return Convert.ToHexString(mac).ToLowerInvariant();
    }
}
