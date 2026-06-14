using System.Runtime.InteropServices;
using static Kseal.Desktop.NativeMethods;

namespace Kseal.Desktop;

/// <summary>Weighted risk score plus the confidence the core derived for it.</summary>
public readonly record struct CoreRiskScore(uint Score, Confidence Confidence);

/// <summary>
/// Typed classification for every error the kseal SDK can raise. Callers branch
/// on <see cref="TrustCoreException.Code"/> instead of parsing a message string.
/// The FFI-backed values mirror the trust core's C ABI status codes one-to-one
/// (see <c>kseal.h</c> / <c>Status</c> in <c>kseal-ffi</c>); the remaining values
/// describe SDK-level precondition failures that never reach the core.
/// </summary>
public enum KsealErrorCode
{
    /// <summary>A request proof was requested before a trust token was set.</summary>
    TrustTokenMissing,
    /// <summary>The trust core could not be created (e.g. malformed key arguments).</summary>
    CoreInitializationFailed,
    /// <summary>A signed config was rejected (bad signature, rollback, or decode failure).</summary>
    ConfigRejected,
    /// <summary>An argument was null or otherwise invalid at the FFI boundary.</summary>
    InvalidArgument,
    /// <summary>A protobuf payload failed to decode.</summary>
    DecodeFailed,
    /// <summary>A cryptographic operation failed.</summary>
    CryptoFailed,
    /// <summary>Serialization/compression on the telemetry transport path failed.</summary>
    TransportFailed,
    /// <summary>An unexpected internal failure (should not occur in normal operation).</summary>
    InternalError,
}

/// <summary>
/// Raised when the kseal SDK fails. Carries a typed <see cref="Code"/> for
/// branching plus a human-readable message for logs/diagnostics (no PII).
/// </summary>
public sealed class TrustCoreException : Exception
{
    /// <summary>Typed classification of the failure; switch on this rather than the message.</summary>
    public KsealErrorCode Code { get; }

    public TrustCoreException(KsealErrorCode code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    /// <summary>Convenience for paths without a granular status; defaults to <see cref="KsealErrorCode.InternalError"/>.</summary>
    public TrustCoreException(string message) : this(KsealErrorCode.InternalError, message) { }

    /// <summary>Maps a raw FFI status code (<c>kseal-ffi</c> <c>Status</c>) to a typed code.</summary>
    public static KsealErrorCode CodeFromStatus(int status) => status switch
    {
        -1 or -3 => KsealErrorCode.InvalidArgument, // ErrNull, ErrInvalid
        -2 => KsealErrorCode.DecodeFailed, // ErrDecode
        -4 => KsealErrorCode.CryptoFailed, // ErrCrypto
        -5 => KsealErrorCode.TransportFailed, // ErrTransport
        _ => KsealErrorCode.InternalError, // ErrPanic / unknown
    };
}

/// <summary>High-level handle to the Rust trust core, hiding the raw FFI surface.</summary>
public interface ITrustCore : IDisposable
{
    string Version { get; }
    void LoadConfig(byte[] signedConfigBytes);
    bool TryLoadConfig(byte[] signedConfigBytes);
    CoreRiskScore EvaluateRisk(ulong riskBits);
    TrustLevel ComputeRiskLevel(ulong riskBits);
    (CoreRiskScore Score, TrustLevel Level) EvaluateRiskAndLevel(ulong riskBits);
    byte[] CreateEvent(EventType eventType, ulong riskBits, Confidence confidence,
        string buildHash, string policyHash, string installKeyHash, long coarseTimeBucket, string? country);
    byte[] BatchAndCompress(IReadOnlyList<byte[]> events);
    byte[] GenerateRequestProof(string tokenId, byte[] requestHash, byte[] nonce, long sequence);
    byte[] GenerateNonce(int length);
    byte[] Compress(byte[] data, int level);
    byte[] Decompress(byte[] data);
}

/// <summary>
/// Real trust core backed by the Rust <c>kseal-ffi</c> C ABI. Owns an opaque
/// core handle for its lifetime (released on <see cref="Dispose"/>).
///
/// The Rust core is internally synchronized (config mutation takes its exclusive
/// lock; readers share it), so the C ABI is safe to call concurrently. A
/// reader-writer lock here additionally guarantees the handle is not freed while
/// a call is in flight, and keeps a score+level pair on one policy snapshot.
/// </summary>
public sealed unsafe class NativeTrustCore : ITrustCore
{
    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.NoRecursion);
    private IntPtr _handle;
    private int _disposed;

    private NativeTrustCore(IntPtr handle) => _handle = handle;

    /// <summary>Creates a core instance.</summary>
    /// <param name="configPublicKey">Ed25519 public key (32 bytes) used to verify signed configs.</param>
    /// <param name="proofKey">Instance HMAC key for request proofs (TPM-bound in production).</param>
    public static NativeTrustCore Create(
        byte[] configPublicKey, byte[] proofKey,
        Platform platform = Platform.Unspecified,
        int maxBatchEvents = 0, int riskWindow = 0, int zstdLevel = 0)
    {
        EnsureLoaded();
        IntPtr handle;
        fixed (byte* pk = configPublicKey)
        fixed (byte* proof = proofKey)
        {
            handle = kseal_core_new(
                pk, (nuint)configPublicKey.Length,
                proof, (nuint)proofKey.Length,
                (int)platform,
                (nuint)Math.Max(0, maxBatchEvents),
                (nuint)Math.Max(0, riskWindow),
                zstdLevel);
        }
        if (handle == IntPtr.Zero)
        {
            throw new TrustCoreException(KsealErrorCode.CoreInitializationFailed, "failed to create trust core (bad key arguments?)");
        }
        return new NativeTrustCore(handle);
    }

    public string Version
    {
        get
        {
            byte* cstr = kseal_version();
            return cstr == null ? "" : Marshal.PtrToStringUTF8((IntPtr)cstr) ?? "";
        }
    }

    public void LoadConfig(byte[] signedConfigBytes)
    {
        if (!TryLoadConfig(signedConfigBytes))
        {
            throw new TrustCoreException(KsealErrorCode.ConfigRejected, "loadConfig failed");
        }
    }

    public bool TryLoadConfig(byte[] signedConfigBytes)
    {
        _lock.EnterWriteLock();
        try
        {
            fixed (byte* b = signedConfigBytes)
            {
                return kseal_load_config(_handle, b, (nuint)signedConfigBytes.Length) == 0;
            }
        }
        finally { _lock.ExitWriteLock(); }
    }

    public CoreRiskScore EvaluateRisk(ulong riskBits)
    {
        _lock.EnterReadLock();
        try { return UnsafeEvaluateRisk(riskBits); }
        finally { _lock.ExitReadLock(); }
    }

    public TrustLevel ComputeRiskLevel(ulong riskBits)
    {
        _lock.EnterReadLock();
        try { return (TrustLevel)kseal_compute_risk_level(_handle, riskBits); }
        finally { _lock.ExitReadLock(); }
    }

    public (CoreRiskScore Score, TrustLevel Level) EvaluateRiskAndLevel(ulong riskBits)
    {
        // One lock acquisition keeps score and level on the same policy: a config
        // swap (write lock) cannot interleave between the two FFI reads.
        _lock.EnterReadLock();
        try { return (UnsafeEvaluateRisk(riskBits), (TrustLevel)kseal_compute_risk_level(_handle, riskBits)); }
        finally { _lock.ExitReadLock(); }
    }

    private CoreRiskScore UnsafeEvaluateRisk(ulong riskBits)
    {
        uint score = 0;
        int confidence = 0;
        int status = kseal_evaluate_risk(_handle, riskBits, &score, &confidence);
        if (status != 0) throw new TrustCoreException(TrustCoreException.CodeFromStatus(status), $"evaluateRisk failed: status={status}");
        return new CoreRiskScore(score, (Confidence)confidence);
    }

    public byte[] CreateEvent(EventType eventType, ulong riskBits, Confidence confidence,
        string buildHash, string policyHash, string installKeyHash, long coarseTimeBucket, string? country)
    {
        _lock.EnterReadLock();
        try
        {
            using var build = new CString(buildHash);
            using var policy = new CString(policyHash);
            using var install = new CString(installKeyHash);
            using var countryStr = new CString(country);
            KsealBuffer outBuf = default;
            int status = kseal_create_event(
                _handle, (int)eventType, riskBits, (int)confidence,
                build.Ptr, policy.Ptr, install.Ptr, coarseTimeBucket, countryStr.Ptr, &outBuf);
            return Consume("createEvent", status, ref outBuf);
        }
        finally { _lock.ExitReadLock(); }
    }

    public byte[] BatchAndCompress(IReadOnlyList<byte[]> events)
    {
        _lock.EnterReadLock();
        try
        {
            // Pin every event buffer for the duration of the call.
            var handles = new GCHandle[events.Count];
            var views = new KsealBytesView[events.Count];
            try
            {
                for (int i = 0; i < events.Count; i++)
                {
                    handles[i] = GCHandle.Alloc(events[i], GCHandleType.Pinned);
                    views[i] = new KsealBytesView
                    {
                        Data = (byte*)handles[i].AddrOfPinnedObject(),
                        Len = (nuint)events[i].Length,
                    };
                }
                KsealBuffer outBuf = default;
                fixed (KsealBytesView* v = views)
                {
                    int status = kseal_batch_and_compress(_handle, v, (nuint)views.Length, &outBuf);
                    return Consume("batchAndCompress", status, ref outBuf);
                }
            }
            finally
            {
                foreach (var h in handles)
                {
                    if (h.IsAllocated) h.Free();
                }
            }
        }
        finally { _lock.ExitReadLock(); }
    }

    public byte[] GenerateRequestProof(string tokenId, byte[] requestHash, byte[] nonce, long sequence)
    {
        _lock.EnterReadLock();
        try
        {
            using var token = new CString(tokenId);
            KsealBuffer outBuf = default;
            fixed (byte* rh = requestHash)
            fixed (byte* nc = nonce)
            {
                int status = kseal_generate_request_proof(
                    _handle, token.Ptr, rh, (nuint)requestHash.Length, nc, (nuint)nonce.Length, sequence, &outBuf);
                return Consume("generateRequestProof", status, ref outBuf);
            }
        }
        finally { _lock.ExitReadLock(); }
    }

    public byte[] GenerateNonce(int length)
    {
        KsealBuffer outBuf = default;
        int status = kseal_generate_nonce((nuint)Math.Max(0, length), &outBuf);
        return Consume("generateNonce", status, ref outBuf);
    }

    public byte[] Compress(byte[] data, int level)
    {
        KsealBuffer outBuf = default;
        fixed (byte* d = data)
        {
            int status = kseal_compress(d, (nuint)data.Length, level, &outBuf);
            return Consume("compress", status, ref outBuf);
        }
    }

    public byte[] Decompress(byte[] data)
    {
        KsealBuffer outBuf = default;
        fixed (byte* d = data)
        {
            int status = kseal_decompress(d, (nuint)data.Length, &outBuf);
            return Consume("decompress", status, ref outBuf);
        }
    }

    /// <summary>Copies an out-buffer to managed memory and frees the native allocation.</summary>
    private static byte[] Consume(string op, int status, ref KsealBuffer buffer)
    {
        if (status != 0)
        {
            kseal_buffer_free(buffer);
            throw new TrustCoreException(TrustCoreException.CodeFromStatus(status), $"{op} failed: status={status}");
        }
        if (buffer.Data == null || buffer.Len == 0)
        {
            kseal_buffer_free(buffer);
            return [];
        }
        var managed = new byte[(int)buffer.Len];
        Marshal.Copy((IntPtr)buffer.Data, managed, 0, managed.Length);
        kseal_buffer_free(buffer);
        return managed;
    }

    public void Dispose()
    {
        // Idempotent: a second Dispose must not touch the already-disposed lock.
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _lock.EnterWriteLock();
        try
        {
            if (_handle != IntPtr.Zero)
            {
                kseal_core_free(_handle);
                _handle = IntPtr.Zero;
            }
        }
        finally
        {
            _lock.ExitWriteLock();
            _lock.Dispose();
        }
    }

    /// <summary>
    /// Verifies an Ed25519 signature over <paramref name="config"/> bytes
    /// (stateless helper).
    /// </summary>
    public static bool VerifyConfigSignature(byte[] config, byte[] signature, byte[] publicKey)
    {
        EnsureLoaded();
        fixed (byte* c = config)
        fixed (byte* s = signature)
        fixed (byte* p = publicKey)
        {
            return kseal_verify_config_signature(
                c, (nuint)config.Length, s, (nuint)signature.Length, p, (nuint)publicKey.Length) == 1;
        }
    }
}

/// <summary>NUL-terminated UTF-8 string pinned for a single P/Invoke call.</summary>
internal sealed unsafe class CString : IDisposable
{
    private readonly IntPtr _ptr;
    public byte* Ptr => (byte*)_ptr;

    public CString(string? value)
    {
        _ptr = value is null ? IntPtr.Zero : Marshal.StringToCoTaskMemUTF8(value);
    }

    public void Dispose()
    {
        if (_ptr != IntPtr.Zero) Marshal.FreeCoTaskMem(_ptr);
    }
}
