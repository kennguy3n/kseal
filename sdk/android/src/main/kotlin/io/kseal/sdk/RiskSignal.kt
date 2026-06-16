package io.kseal.sdk

/**
 * Packed risk signals observed on-device.
 *
 * The [bit] indices mirror, exactly, the Rust core's `RiskBitset`
 * (`sdk/rust-core/kseal-core/src/risk.rs`) and the `kseal.v1.RiskBitset` wire
 * type. The native probes set these bits; the Rust trust core decodes the same
 * layout. **Do not renumber** — only append new signals at higher positions.
 */
enum class RiskSignal(val bit: Int) {
    /** Android root (su/Magisk) detected. */
    ROOT(0),

    /** iOS jailbreak detected. (Unused on Android; present for layout parity.) */
    JAILBREAK(1),

    /** Running under an Android emulator. */
    EMULATOR(2),

    /** Running under the iOS simulator. (Unused on Android.) */
    SIMULATOR(3),

    /** A debugger is attached. */
    DEBUGGER(4),

    /** Hooking framework (Frida/Xposed/objection) present. */
    HOOKING(5),

    /** Runtime in-memory tamper (code/section checksum mismatch). */
    TAMPER(6),

    /** App-integrity mismatch (repackaging / resigning). */
    APP_INTEGRITY(7),

    /** Network MITM / interception detected. */
    NETWORK_MITM(8),

    /** Generic elevated-environment risk. */
    ENVIRONMENT(9),

    /** A system HTTP proxy is configured. */
    PROXY(10),

    /** A user-installed CA is trusted. */
    USER_CA(11),

    /** TLS certificate pinning failed. */
    PINNING_FAILURE(12),

    /** Platform attestation failed or was unavailable. */
    ATTESTATION_FAIL(13),

    /** Hardware-backed keystore/enclave unavailable. */
    SECURE_HW_MISSING(14),

    /** Signing certificate mismatch (repackaged binary). */
    REPACKAGED(15),

    /** The screen is being captured or recorded (credential/OTP exfiltration). */
    SCREEN_CAPTURE(16),

    /** A tapjacking/overlay window is drawn over the app (UI redress). */
    OVERLAY_ABUSE(17),

    /** An abusive accessibility service is active (input/UI hijack). */
    ACCESSIBILITY_ABUSE(18),

    /** A malicious or untrusted input method (keyboard) is active. */
    MALICIOUS_IME(19),

    /** A remote-access / screen-sharing tool is controlling the device. */
    REMOTE_ACCESS(20);

    /** This signal as a single-bit mask in the packed `u64`. */
    val mask: Long get() = 1L shl bit

    companion object {
        /** Packs a set of signals into the `u64` bitset the Rust core consumes. */
        fun pack(signals: Iterable<RiskSignal>): Long =
            signals.fold(0L) { acc, s -> acc or s.mask }

        /** Decodes the named signals present in a packed bitset. */
        fun unpack(bits: Long): Set<RiskSignal> =
            entries.filterTo(LinkedHashSet()) { bits and it.mask != 0L }
    }
}
