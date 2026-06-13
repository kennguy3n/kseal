import Foundation

/// Packed risk signals observed on-device.
///
/// The `bit` indices mirror, exactly, the Rust core's `RiskBitset`
/// (`sdk/rust-core/kseal-core/src/risk.rs`) and the `kseal.v1.RiskBitset` wire
/// type. Native probes set these bits; the Rust trust core decodes the same
/// layout. **Do not renumber** — only append new signals at higher positions.
public enum RiskSignal: Int, CaseIterable, Sendable {
    /// Android root detected. (Unused on iOS; present for layout parity.)
    case root = 0
    /// iOS jailbreak detected.
    case jailbreak = 1
    /// Running under an Android emulator. (Unused on iOS.)
    case emulator = 2
    /// Running under the iOS simulator.
    case simulator = 3
    /// A debugger is attached.
    case debugger = 4
    /// Hooking framework (Frida/Substrate/Cycript) present.
    case hooking = 5
    /// Runtime in-memory tamper (code/section checksum mismatch).
    case tamper = 6
    /// App-integrity mismatch (repackaging / resigning).
    case appIntegrity = 7
    /// Network MITM / interception detected.
    case networkMitm = 8
    /// Generic elevated-environment risk.
    case environment = 9
    /// A system HTTP proxy is configured.
    case proxy = 10
    /// A user-installed CA is trusted.
    case userCa = 11
    /// TLS certificate pinning failed.
    case pinningFailure = 12
    /// Platform attestation failed or was unavailable.
    case attestationFail = 13
    /// Hardware-backed Secure Enclave unavailable.
    case secureHwMissing = 14
    /// Signing/provisioning mismatch (repackaged binary).
    case repackaged = 15

    /// This signal as a single-bit mask in the packed `u64`.
    public var mask: UInt64 { UInt64(1) << UInt64(rawValue) }

    /// Packs a set of signals into the `u64` bitset the Rust core consumes.
    public static func pack(_ signals: Set<RiskSignal>) -> UInt64 {
        signals.reduce(UInt64(0)) { $0 | $1.mask }
    }

    /// Decodes the named signals present in a packed bitset.
    public static func unpack(_ bits: UInt64) -> Set<RiskSignal> {
        Set(allCases.filter { bits & $0.mask != 0 })
    }
}
