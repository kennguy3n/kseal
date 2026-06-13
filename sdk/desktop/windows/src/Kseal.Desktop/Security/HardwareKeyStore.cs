using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Kseal.Desktop;

/// <summary>
/// Binds at-rest key material to a hardware-backed key where the platform offers
/// one (Windows TPM via the CNG Platform Crypto Provider), with a clean software
/// fallback. The request-proof HMAC key is sealed before it is persisted, so the
/// on-disk secret cannot be lifted and replayed from another device — yet the
/// <b>request-proof byte layout is unchanged</b>: the core still computes
/// <c>HMAC(proofKey, …)</c>; only how <c>proofKey</c> is protected at rest changes.
///
/// This is the <b>external secure-element mock boundary</b>: tests inject a fake
/// store so the proof-binding logic is exercised deterministically on any host.
/// </summary>
public interface IHardwareKeyStore
{
    /// <summary>
    /// Whether sealed blobs are bound to a hardware-backed key (vs. a software
    /// fallback). Surfaced so a policy can require hardware binding and fail
    /// closed when it is unavailable.
    /// </summary>
    bool IsHardwareBacked { get; }

    /// <summary>Wraps <paramref name="plaintext"/> into an opaque blob safe to persist.</summary>
    /// <exception cref="HardwareKeyStoreException">If the hardware element rejects the operation.</exception>
    byte[] Seal(byte[] plaintext);

    /// <summary>Unwraps a blob previously produced by <see cref="Seal"/>.</summary>
    /// <exception cref="HardwareKeyStoreException">If the blob was not produced by this store/device.</exception>
    byte[] Unseal(byte[] sealedBlob);
}

/// <summary>Raised when a hardware key operation cannot complete.</summary>
public sealed class HardwareKeyStoreException : Exception
{
    public HardwareKeyStoreException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// Transparent software fallback: the "sealed" blob is the plaintext, so the
/// persisted key is byte-identical to the portable file-backed default. Used
/// when no hardware element is available (e.g. CI, virtualized hosts).
/// <see cref="IsHardwareBacked"/> is false so callers can require hardware and
/// fail closed when configured to.
/// </summary>
public sealed class SoftwareKeyStore : IHardwareKeyStore
{
    public bool IsHardwareBacked => false;
    public byte[] Seal(byte[] plaintext) => plaintext;
    public byte[] Unseal(byte[] sealedBlob) => sealedBlob;
}

/// <summary>
/// Returns the production hardware key store for the current platform: a
/// TPM-backed store on Windows when a TPM is present, the software fallback
/// elsewhere (or when no TPM is available).
/// </summary>
internal static class HardwareKeyStoreFactory
{
    public static IHardwareKeyStore Create(string label)
    {
        if (OperatingSystem.IsWindows())
        {
            IHardwareKeyStore? tpm = TpmHardwareKeyStore.TryCreate(label);
            if (tpm is not null) return tpm;
        }
        return new SoftwareKeyStore();
    }
}

/// <summary>
/// Windows TPM-backed key store.
///
/// A non-exportable 2048-bit RSA key is created on first use in the
/// <b>Microsoft Platform Crypto Provider</b> (the TPM-backed CNG provider) and
/// persisted under a tenant/app-scoped key name. Sealing RSA-OAEP-SHA256
/// encrypts the proof key to that key; unsealing performs the decryption
/// <b>inside the TPM</b> — the private key never leaves the chip and the sealed
/// blob is useless on any other machine. When no TPM/provider is available
/// <see cref="TryCreate"/> returns null and the caller uses the software fallback.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class TpmHardwareKeyStore : IHardwareKeyStore
{
    private const string ProviderName = "Microsoft Platform Crypto Provider";
    private const int KeySizeBits = 2048;

    private readonly string _keyName;

    private TpmHardwareKeyStore(string keyName) => _keyName = keyName;

    /// <summary>
    /// Materializes (or opens) the TPM key, returning null when the TPM/provider
    /// is unavailable so the caller can fall back rather than degrade silently.
    /// </summary>
    public static TpmHardwareKeyStore? TryCreate(string label)
    {
        string keyName = $"io.kseal.proofkey.{label}";
        try
        {
            using CngKey key = OpenOrCreate(keyName);
            return new TpmHardwareKeyStore(keyName);
        }
        catch (CryptographicException) { return null; }
        catch (PlatformNotSupportedException) { return null; }
    }

    public bool IsHardwareBacked => true;

    public byte[] Seal(byte[] plaintext)
    {
        try
        {
            using CngKey key = CngKey.Open(_keyName, new CngProvider(ProviderName));
            using var rsa = new RSACng(key);
            return rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException e)
        {
            throw new HardwareKeyStoreException("TPM seal failed", e);
        }
    }

    public byte[] Unseal(byte[] sealedBlob)
    {
        try
        {
            using CngKey key = CngKey.Open(_keyName, new CngProvider(ProviderName));
            using var rsa = new RSACng(key);
            return rsa.Decrypt(sealedBlob, RSAEncryptionPadding.OaepSHA256);
        }
        catch (CryptographicException e)
        {
            throw new HardwareKeyStoreException("TPM unseal failed", e);
        }
    }

    private static CngKey OpenOrCreate(string keyName)
    {
        var provider = new CngProvider(ProviderName);
        if (CngKey.Exists(keyName, provider)) return CngKey.Open(keyName, provider);

        var parameters = new CngKeyCreationParameters
        {
            Provider = provider,
            // Persisted machine key; never exportable so the private half is
            // pinned to this TPM.
            KeyCreationOptions = CngKeyCreationOptions.MachineKey,
            ExportPolicy = CngExportPolicies.None,
        };
        parameters.Parameters.Add(new CngProperty(
            "Length", BitConverter.GetBytes(KeySizeBits), CngPropertyOptions.None));
        return CngKey.Create(CngAlgorithm.Rsa, keyName, parameters);
    }
}
