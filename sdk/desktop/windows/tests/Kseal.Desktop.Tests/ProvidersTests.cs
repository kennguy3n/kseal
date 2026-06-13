using Xunit;

namespace Kseal.Desktop.Tests;

public class ProvidersTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"kseal-test-{Guid.NewGuid():N}");

    public ProvidersTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void StorageScopeIsStableAndTenantAppSpecific()
    {
        string a = StorageScope.Component("tenant-1", "app-1");
        Assert.Equal(a, StorageScope.Component("tenant-1", "app-1"));       // deterministic
        Assert.NotEqual(a, StorageScope.Component("tenant-2", "app-1"));    // tenant matters
        Assert.NotEqual(a, StorageScope.Component("tenant-1", "app-2"));    // app matters
        // No path separators / unsafe chars (lowercase hex only).
        Assert.Matches("^[0-9a-f]+$", a);
    }

    [Fact]
    public void AtomicWriteReplacesExistingContent()
    {
        string path = Path.Combine(_dir, "config.bin");
        AtomicFile.Write(path, [1, 2, 3]);
        AtomicFile.Write(path, [4, 5]);
        Assert.Equal([4, 5], File.ReadAllBytes(path));
        // No temp files left behind.
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
    }

    [Fact]
    public void CreateOrReadExistingKeepsTheFirstWriter()
    {
        string path = Path.Combine(_dir, "proof.key");
        byte[] first = AtomicFile.CreateOrReadExisting(path, [1, 1, 1]);
        byte[] second = AtomicFile.CreateOrReadExisting(path, [2, 2, 2]);
        Assert.Equal([1, 1, 1], first);
        Assert.Equal(first, second); // loser adopts the winner's bytes
    }

    [Fact]
    public void ProofKeyAndInstallIdAreStableAcrossInstances()
    {
        byte[] key1 = new DefaultProofKeyProvider(_dir).ProofKey();
        byte[] key2 = new DefaultProofKeyProvider(_dir).ProofKey();
        Assert.Equal(32, key1.Length);
        Assert.Equal(key1, key2);

        string hash1 = new InstallIdentity(_dir).TenantScopedHash("t", "a");
        string hash2 = new InstallIdentity(_dir).TenantScopedHash("t", "a");
        Assert.Equal(hash1, hash2);
    }
}
