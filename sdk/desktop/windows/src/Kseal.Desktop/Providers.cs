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
/// Derives a filesystem-safe, collision-resistant directory component that
/// isolates one tenant+app's private storage (config, proof key, install id)
/// from every other tenant/app sharing the same user account.
/// </summary>
internal static class StorageScope
{
    public static string Component(string tenantId, string appId)
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes($"{tenantId}\0{appId}"));
        return Convert.ToHexString(digest.AsSpan(0, 16)).ToLowerInvariant();
    }
}

/// <summary>Atomic, race-tolerant file helpers for first-launch secrets/config.</summary>
internal static class AtomicFile
{
    /// <summary>
    /// Writes <paramref name="bytes"/> to a sibling temp file then atomically
    /// renames it over <paramref name="path"/>, so a crash mid-write never leaves
    /// a partially written target.
    /// </summary>
    public static void Write(string path, byte[] bytes)
    {
        string tmp = $"{path}.{Guid.NewGuid():N}.tmp";
        File.WriteAllBytes(tmp, bytes);
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>
    /// Materializes a first-launch secret tolerating a concurrent creator: the
    /// exclusive <see cref="FileMode.CreateNew"/> makes the create-vs-create race
    /// a loser-reads situation, so every caller converges on a single value (no
    /// last-writer-wins churn).
    /// </summary>
    public static byte[] CreateOrReadExisting(string path, byte[] candidate)
    {
        try
        {
            using var fs = new FileStream(
                path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            fs.Write(candidate, 0, candidate.Length);
            return candidate;
        }
        catch (IOException)
        {
            // Lost the race (file already exists): adopt the winner's bytes.
            byte[] existing = File.ReadAllBytes(path);
            return existing.Length > 0 ? existing : candidate;
        }
    }
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
    public void Persist(byte[] config) => AtomicFile.Write(_path, config);
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
        return AtomicFile.CreateOrReadExisting(_path, RandomNumberGenerator.GetBytes(32));
    }
}

/// <summary>
/// Proof-key provider that seals the request-proof HMAC key with an
/// <see cref="IHardwareKeyStore"/> before persisting it.
///
/// With a hardware-backed store (Windows TPM) the at-rest key is bound to the
/// device's secure element and cannot be lifted from disk and replayed
/// elsewhere. With the software fallback the persisted bytes are byte-identical
/// to <see cref="DefaultProofKeyProvider"/>, so existing installs keep their key
/// — and thus their server-side trust continuity. The request-proof byte layout
/// is unchanged either way: the core still computes <c>HMAC(proofKey, …)</c>;
/// only how <c>proofKey</c> is protected at rest changes.
/// </summary>
public sealed class HardwareBoundProofKeyProvider : IProofKeyProvider
{
    public const int KeyLength = 32;

    private readonly string _path;
    private readonly IHardwareKeyStore _store;

    public HardwareBoundProofKeyProvider(string directory, IHardwareKeyStore store)
    {
        string dir = Path.Combine(directory, "kseal");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "proof.key");
        _store = store;
    }

    /// <summary>Whether the persisted key is sealed by a hardware-backed element.</summary>
    public bool IsHardwareBacked => _store.IsHardwareBacked;

    public byte[] ProofKey()
    {
        if (File.Exists(_path))
        {
            byte[] stored = File.ReadAllBytes(_path);
            if (stored.Length > 0)
            {
                byte[]? key = TryUnseal(stored);
                if (key is { Length: KeyLength }) return key;

                // A blob we cannot unseal but that is exactly a legacy raw key:
                // adopt it (preserving trust continuity) and re-seal it in place.
                if (stored.Length == KeyLength)
                {
                    byte[]? resealed = TrySeal(stored);
                    if (resealed is not null) AtomicFile.Write(_path, resealed);
                    return stored;
                }
                // Otherwise the blob is unusable — regenerate below.
            }
        }

        byte[] fresh = RandomNumberGenerator.GetBytes(KeyLength);
        byte[]? sealedBytes = TrySeal(fresh);
        if (sealedBytes is null)
        {
            // Hardware seal failed unexpectedly: persist the raw key so the SDK
            // stays functional (software-equivalent) rather than bricking the host.
            return AtomicFile.CreateOrReadExisting(_path, fresh);
        }

        byte[] persisted = AtomicFile.CreateOrReadExisting(_path, sealedBytes);
        // Re-unseal the race winner's blob so concurrent creators converge.
        byte[]? unsealed = TryUnseal(persisted);
        return unsealed is { Length: KeyLength } ? unsealed : fresh;
    }

    private byte[]? TrySeal(byte[] plaintext)
    {
        try { return _store.Seal(plaintext); }
        catch (HardwareKeyStoreException) { return null; }
    }

    private byte[]? TryUnseal(byte[] sealedBlob)
    {
        try { return _store.Unseal(sealedBlob); }
        catch (HardwareKeyStoreException) { return null; }
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
        return AtomicFile.CreateOrReadExisting(_path, RandomNumberGenerator.GetBytes(16));
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
