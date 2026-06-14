package io.kseal.sdk

/**
 * Typed classification for every error the kseal SDK can raise. Callers branch
 * on the [KsealException.code] instead of parsing a message string.
 *
 * The FFI-backed codes mirror the trust core's C ABI status codes one-to-one
 * (see `kseal.h` / `Status` in `kseal-ffi`); the remaining codes describe
 * SDK-level precondition failures that never reach the core.
 */
enum class KsealErrorCode {
    /** A request proof was requested before a trust token was set; complete
     * attestation and call [KsealSDK.setTrustToken] first. */
    TRUST_TOKEN_MISSING,

    /** The trust core could not be created (e.g. malformed key arguments). */
    CORE_INITIALIZATION_FAILED,

    /** A signed config was rejected (bad signature, rollback, or decode failure). */
    CONFIG_REJECTED,

    /** An argument was null or otherwise invalid at the FFI boundary. */
    INVALID_ARGUMENT,

    /** A protobuf payload failed to decode. */
    DECODE_FAILED,

    /** A cryptographic operation failed. */
    CRYPTO_FAILED,

    /** Serialization/compression on the telemetry transport path failed. */
    TRANSPORT_FAILED,

    /** An unexpected internal failure (should not occur in normal operation). */
    INTERNAL_ERROR;

    companion object {
        /** Maps a raw FFI status code (`kseal-ffi` `Status`) to a typed code. */
        @JvmStatic
        fun fromStatus(status: Int): KsealErrorCode = when (status) {
            -1, -3 -> INVALID_ARGUMENT // ErrNull, ErrInvalid
            -2 -> DECODE_FAILED // ErrDecode
            -4 -> CRYPTO_FAILED // ErrCrypto
            -5 -> TRANSPORT_FAILED // ErrTransport
            else -> INTERNAL_ERROR // ErrPanic / unknown
        }
    }
}

/**
 * Error raised by the kseal SDK.
 *
 * Carries a typed [code] for branching plus a human-readable message for
 * logs/diagnostics. Messages never contain PII.
 */
open class KsealException(
    /** Typed classification of the failure; branch on this rather than the message. */
    val code: KsealErrorCode,
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)
