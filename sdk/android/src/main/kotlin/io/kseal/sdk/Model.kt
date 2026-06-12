package io.kseal.sdk

/**
 * Coarse confidence in a signal or decision. Mirrors `kseal.v1.Confidence`.
 */
enum class Confidence(val code: Int) {
    UNSPECIFIED(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3);

    companion object {
        fun fromCode(code: Int): Confidence = entries.firstOrNull { it.code == code } ?: UNSPECIFIED
    }
}

/**
 * Fused trust classification for an app instance. Mirrors `kseal.v1.TrustLevel`.
 *
 * `UNSPECIFIED` is reported when no signed policy is loaded (thresholds are
 * required to map a score to a level).
 */
enum class TrustLevel(val code: Int) {
    UNSPECIFIED(0),
    TRUSTED(1),
    LOW_RISK(2),
    MEDIUM_RISK(3),
    HIGH_RISK(4),
    CRITICAL(5);

    companion object {
        fun fromCode(code: Int): TrustLevel = entries.firstOrNull { it.code == code } ?: UNSPECIFIED
    }
}

/**
 * Telemetry event categories emitted by the SDK. Mirrors `kseal.v1.EventType`.
 */
enum class EventType(val code: Int) {
    UNSPECIFIED(0),
    RUNTIME_TAMPER(1),
    DEBUGGER(2),
    ROOT_RISK(3),
    ATTESTATION_FAIL(4),
    NETWORK_MITM(5),
    POLICY_DECISION(6),
    HOOKING_DETECTED(7),
    APP_INTEGRITY_FAIL(8),
    ENVIRONMENT_RISK(9);
}

/** Reporting platform. Mirrors `kseal.v1.Platform`. */
enum class Platform(val code: Int) {
    UNSPECIFIED(0),
    ANDROID(1),
    IOS(2);
}

/**
 * Result of an on-device risk evaluation.
 *
 * @property riskBits packed signal bitset (the only thing handed to the core / server).
 * @property signals decoded set of detected signals (for local logging/UX; never exported raw).
 * @property score weighted risk score from the trust core's active policy (default weights when none loaded).
 * @property confidence coarse confidence derived from the signal mix.
 * @property trustLevel fused trust level under the active policy, or [TrustLevel.UNSPECIFIED] when no policy is loaded.
 */
data class RiskAssessment(
    val riskBits: Long,
    val signals: Set<RiskSignal>,
    val score: Int,
    val confidence: Confidence,
    val trustLevel: TrustLevel,
) {
    /** Whether no risk signals were observed. */
    val isClean: Boolean get() = riskBits == 0L
}

/**
 * Per-request proof binding a request to the current trust token.
 *
 * [proofBytes] is the serialized `kseal.v1.RequestProof` the host attaches to
 * the outbound request (e.g. as a header); the remaining fields are the inputs
 * the SDK supplied, surfaced for convenience and assertions.
 */
data class RequestProof(
    val tokenId: String,
    val requestHash: ByteArray,
    val nonce: ByteArray,
    val sequence: Long,
    val proofBytes: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RequestProof) return false
        return tokenId == other.tokenId &&
            sequence == other.sequence &&
            requestHash.contentEquals(other.requestHash) &&
            nonce.contentEquals(other.nonce) &&
            proofBytes.contentEquals(other.proofBytes)
    }

    override fun hashCode(): Int {
        var result = tokenId.hashCode()
        result = 31 * result + sequence.hashCode()
        result = 31 * result + requestHash.contentHashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + proofBytes.contentHashCode()
        return result
    }
}
