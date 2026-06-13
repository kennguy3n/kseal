using Xunit;

namespace Kseal.Desktop.Tests;

public class HardwareKeyStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"kseal-hw-{Guid.NewGuid():N}");

    public HardwareKeyStoreTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        GC.SuppressFinalize(this);
    }

    private string KeyPath => Path.Combine(_dir, "kseal", "proof.key");

    [Fact]
    public void SoftwareStorePassesThroughUnchanged()
    {
        var store = new SoftwareKeyStore();
        byte[] data = [1, 2, 3, 4];
        Assert.False(store.IsHardwareBacked);
        Assert.Equal(data, store.Seal(data));
        Assert.Equal(data, store.Unseal(data));
    }

    [Fact]
    public void FakeStoreRoundTripsAndRejectsForeignBlob()
    {
        var store = new FakeHardwareKeyStore();
        byte[] data = [9, 8, 7, 6, 5];
        byte[] sealed_ = store.Seal(data);
        Assert.NotEqual(data, sealed_);                 // actually sealed
        Assert.Equal(data, store.Unseal(sealed_));      // round-trips
        Assert.Throws<HardwareKeyStoreException>(() => store.Unseal([0, 1, 2])); // foreign blob
    }

    [Fact]
    public void HardwareBoundProviderSealsKeyAtRestAndIsStable()
    {
        var store = new FakeHardwareKeyStore();
        var provider = new HardwareBoundProofKeyProvider(_dir, store);

        byte[] key1 = provider.ProofKey();
        Assert.Equal(32, key1.Length);
        Assert.True(provider.IsHardwareBacked);

        // The on-disk blob is sealed, not the raw key.
        byte[] onDisk = File.ReadAllBytes(KeyPath);
        Assert.NotEqual(key1, onDisk);
        Assert.Equal(key1, store.Unseal(onDisk));

        // Stable across provider instances (re-reads + unseals the same key).
        byte[] key2 = new HardwareBoundProofKeyProvider(_dir, store).ProofKey();
        Assert.Equal(key1, key2);
    }

    [Fact]
    public void LegacyRawKeyIsAdoptedAndResealedInPlace()
    {
        // Simulate a pre-hardware install: a raw 32-byte key already on disk.
        Directory.CreateDirectory(Path.GetDirectoryName(KeyPath)!);
        byte[] legacy = new byte[32];
        for (int i = 0; i < 32; i++) legacy[i] = (byte)(i + 1);
        File.WriteAllBytes(KeyPath, legacy);

        var store = new FakeHardwareKeyStore();
        var provider = new HardwareBoundProofKeyProvider(_dir, store);

        byte[] key = provider.ProofKey();
        Assert.Equal(legacy, key); // continuity: same key

        // It was re-sealed in place, so the on-disk bytes are now the sealed blob.
        byte[] onDisk = File.ReadAllBytes(KeyPath);
        Assert.NotEqual(legacy, onDisk);
        Assert.Equal(legacy, store.Unseal(onDisk));
    }

    [Fact]
    public void SealFailureDegradesToRawKeyWithoutBricking()
    {
        var provider = new HardwareBoundProofKeyProvider(_dir, new FailingHardwareKeyStore());
        byte[] key1 = provider.ProofKey();
        Assert.Equal(32, key1.Length);
        // Persisted as raw (software-equivalent) and stable.
        Assert.Equal(key1, File.ReadAllBytes(KeyPath));
        byte[] key2 = new HardwareBoundProofKeyProvider(_dir, new FailingHardwareKeyStore()).ProofKey();
        Assert.Equal(key1, key2);
    }

    [Fact]
    public void DefaultFactoryProducesAUsableStore()
    {
        // On non-Windows CI this is the software fallback; on Windows w/o TPM too.
        IHardwareKeyStore store = HardwareKeyStoreFactory.Create("tenant-app");
        byte[] data = [1, 2, 3];
        Assert.Equal(data, store.Unseal(store.Seal(data)));
    }
}
