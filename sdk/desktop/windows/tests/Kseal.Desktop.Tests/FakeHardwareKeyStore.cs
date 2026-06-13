namespace Kseal.Desktop.Tests;

/// <summary>
/// Deterministic test fake for <see cref="IHardwareKeyStore"/>: prepends a magic
/// header and XOR-obfuscates the payload so a "sealed" blob is distinguishable
/// from the plaintext (a foreign/legacy blob is rejected on unseal). Lets the
/// proof-key sealing logic be exercised on any host without a TPM.
/// </summary>
internal sealed class FakeHardwareKeyStore : IHardwareKeyStore
{
    private static readonly byte[] Magic = "KSEA"u8.ToArray();
    private const byte XorMask = 0x5A;

    public bool IsHardwareBacked => true;

    public byte[] Seal(byte[] plaintext)
    {
        byte[] outBuf = new byte[Magic.Length + plaintext.Length];
        Magic.CopyTo(outBuf, 0);
        for (int i = 0; i < plaintext.Length; i++) outBuf[Magic.Length + i] = (byte)(plaintext[i] ^ XorMask);
        return outBuf;
    }

    public byte[] Unseal(byte[] sealedBlob)
    {
        if (sealedBlob.Length < Magic.Length || !sealedBlob.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new HardwareKeyStoreException("not a blob produced by this store");
        }
        byte[] outBuf = new byte[sealedBlob.Length - Magic.Length];
        for (int i = 0; i < outBuf.Length; i++) outBuf[i] = (byte)(sealedBlob[Magic.Length + i] ^ XorMask);
        return outBuf;
    }
}

/// <summary>A store whose operations always fail, to test graceful software degradation.</summary>
internal sealed class FailingHardwareKeyStore : IHardwareKeyStore
{
    public bool IsHardwareBacked => true;
    public byte[] Seal(byte[] plaintext) => throw new HardwareKeyStoreException("seal unavailable");
    public byte[] Unseal(byte[] sealedBlob) => throw new HardwareKeyStoreException("unseal unavailable");
}
