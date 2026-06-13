namespace Kseal.Desktop;

/// <summary>
/// Packed risk signals observed on-device.
///
/// The bit indices mirror, exactly, the Rust core's <c>RiskBitset</c>
/// (sdk/rust-core/kseal-core/src/risk.rs) and the <c>kseal.v1.RiskBitset</c>
/// wire type, shared across all platform SDKs. Native probes set these bits;
/// the Rust trust core decodes the same layout. <b>Do not renumber</b> — only
/// append new signals at higher positions.
/// </summary>
public enum RiskSignal
{
    Root = 0,
    Jailbreak = 1,
    Emulator = 2,
    Simulator = 3,
    Debugger = 4,
    /// <summary>Hooking / code-injection framework present (DLL injection on Windows).</summary>
    Hooking = 5,
    /// <summary>Runtime in-memory tamper (code/section checksum mismatch).</summary>
    Tamper = 6,
    /// <summary>App-integrity mismatch (repackaging / resigning).</summary>
    AppIntegrity = 7,
    NetworkMitm = 8,
    /// <summary>Generic elevated-environment risk.</summary>
    Environment = 9,
    Proxy = 10,
    UserCa = 11,
    PinningFailure = 12,
    /// <summary>Platform attestation failed or was unavailable.</summary>
    AttestationFail = 13,
    /// <summary>Hardware-backed key store (TPM) unavailable.</summary>
    SecureHwMissing = 14,
    /// <summary>Signing/publisher mismatch (repackaged binary).</summary>
    Repackaged = 15,
}

/// <summary>Pack/unpack helpers between <see cref="RiskSignal"/> sets and the u64 bitset.</summary>
public static class RiskSignals
{
    /// <summary>This signal as a single-bit mask in the packed u64.</summary>
    public static ulong Mask(this RiskSignal signal) => 1UL << (int)signal;

    /// <summary>Packs signals into the u64 bitset the Rust core consumes.</summary>
    public static ulong Pack(IEnumerable<RiskSignal> signals)
    {
        ulong bits = 0;
        foreach (var s in signals) bits |= s.Mask();
        return bits;
    }

    /// <summary>Decodes the named signals present in a packed bitset.</summary>
    public static IReadOnlySet<RiskSignal> Unpack(ulong bits)
    {
        var set = new HashSet<RiskSignal>();
        foreach (RiskSignal s in Enum.GetValues<RiskSignal>())
        {
            if ((bits & s.Mask()) != 0) set.Add(s);
        }
        return set;
    }
}
