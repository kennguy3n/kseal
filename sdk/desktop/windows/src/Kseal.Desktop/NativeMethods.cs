using System.Reflection;
using System.Runtime.InteropServices;

namespace Kseal.Desktop;

/// <summary>
/// P/Invoke declarations for the prebuilt <c>kseal-ffi</c> C ABI (kseal.h),
/// consumed exactly like the mobile SDKs consume the FFI — the Rust crate is
/// not modified. The native library name <c>kseal_ffi</c> resolves to
/// <c>kseal_ffi.dll</c> on Windows, <c>libkseal_ffi.so</c> on Linux, and
/// <c>libkseal_ffi.dylib</c> on macOS.
/// </summary>
internal static unsafe class NativeMethods
{
    private const string Lib = "kseal_ffi";

    /// <summary>
    /// Owned, length-prefixed buffer handed back by the core; release with
    /// <see cref="kseal_buffer_free"/>.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct KsealBuffer
    {
        public byte* Data;
        public nuint Len;
        public nuint Cap;
    }

    /// <summary>Borrowed view of caller-owned bytes (one serialized event).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct KsealBytesView
    {
        public byte* Data;
        public nuint Len;
    }

    static NativeMethods()
    {
        // Let an integrator / the test harness point at a specific build of the
        // shared library via KSEAL_FFI_LIBRARY (absolute path) without changing
        // the OS loader search path.
        NativeLibrary.SetDllImportResolver(typeof(NativeMethods).Assembly, Resolve);
    }

    /// <summary>Forces the static constructor to register the resolver.</summary>
    internal static void EnsureLoaded() { }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != Lib) return IntPtr.Zero; // default handling
        var overridePath = Environment.GetEnvironmentVariable("KSEAL_FFI_LIBRARY");
        if (!string.IsNullOrEmpty(overridePath) && File.Exists(overridePath))
        {
            return NativeLibrary.Load(overridePath);
        }
        return IntPtr.Zero; // fall back to default OS resolution
    }

    [DllImport(Lib)]
    internal static extern byte* kseal_version();

    [DllImport(Lib)]
    internal static extern IntPtr kseal_core_new(
        byte* configPublicKey, nuint configPublicKeyLen,
        byte* proofKey, nuint proofKeyLen,
        int platform, nuint maxBatchEvents, nuint riskWindow, int zstdLevel);

    [DllImport(Lib)]
    internal static extern void kseal_core_free(IntPtr handle);

    [DllImport(Lib)]
    internal static extern int kseal_load_config(IntPtr handle, byte* bytes, nuint len);

    [DllImport(Lib)]
    internal static extern int kseal_evaluate_risk(IntPtr handle, ulong riskBits, uint* outScore, int* outConfidence);

    [DllImport(Lib)]
    internal static extern int kseal_compute_risk_level(IntPtr handle, ulong riskBits);

    [DllImport(Lib)]
    internal static extern int kseal_create_event(
        IntPtr handle, int eventType, ulong riskBits, int confidence,
        byte* buildHash, byte* policyHash, byte* installKeyHash,
        long coarseTimeBucket, byte* country, KsealBuffer* outBuf);

    [DllImport(Lib)]
    internal static extern int kseal_batch_and_compress(IntPtr handle, KsealBytesView* events, nuint count, KsealBuffer* outBuf);

    [DllImport(Lib)]
    internal static extern int kseal_generate_request_proof(
        IntPtr handle, byte* tokenId,
        byte* requestHash, nuint requestHashLen,
        byte* nonce, nuint nonceLen,
        long seq, KsealBuffer* outBuf);

    [DllImport(Lib)]
    internal static extern int kseal_verify_config_signature(
        byte* config, nuint configLen, byte* signature, nuint signatureLen, byte* publicKey, nuint publicKeyLen);

    [DllImport(Lib)]
    internal static extern int kseal_compress(byte* data, nuint len, int level, KsealBuffer* outBuf);

    [DllImport(Lib)]
    internal static extern int kseal_decompress(byte* data, nuint len, KsealBuffer* outBuf);

    [DllImport(Lib)]
    internal static extern int kseal_generate_nonce(nuint len, KsealBuffer* outBuf);

    [DllImport(Lib)]
    internal static extern void kseal_buffer_free(KsealBuffer buffer);
}
