package io.kseal.sdk.internal

import io.kseal.sdk.Confidence
import io.kseal.sdk.EventType
import io.kseal.sdk.Platform
import io.kseal.sdk.TrustLevel

/** Weighted risk score plus the confidence the core derived for it. */
internal data class CoreRiskScore(val score: Int, val confidence: Confidence)

/**
 * High-level handle to the Rust trust core, hiding the raw FFI/JNI surface.
 *
 * This is the seam the platform SDK is built on. The production implementation,
 * [NativeTrustCore], delegates to the real Rust core over JNI; there is no
 * stubbed/faked core — tests run the same implementation against a host build
 * of the library.
 */
internal interface TrustCore : AutoCloseable {
    val version: String

    /** Installs a signed, serialized `kseal.v1.SignedConfig`. */
    fun loadConfig(signedConfigBytes: ByteArray)

    /** Verifies and installs config, returning `false` on a rejected/invalid config. */
    fun tryLoadConfig(signedConfigBytes: ByteArray): Boolean

    fun evaluateRisk(riskBits: Long): CoreRiskScore

    fun computeRiskLevel(riskBits: Long): TrustLevel

    fun createEvent(
        eventType: EventType,
        riskBits: Long,
        confidence: Confidence,
        buildHash: String,
        policyHash: String,
        installKeyHash: String,
        coarseTimeBucket: Long,
        country: String?,
    ): ByteArray

    fun batchAndCompress(events: List<ByteArray>): ByteArray

    fun generateRequestProof(
        tokenId: String,
        requestHash: ByteArray,
        nonce: ByteArray,
        sequence: Long,
    ): ByteArray

    fun generateNonce(length: Int): ByteArray

    fun compress(data: ByteArray, level: Int = 0): ByteArray

    fun decompress(data: ByteArray): ByteArray

    companion object {
        /** Verifies an Ed25519 signature over `config` bytes. */
        fun verifyConfigSignature(config: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
            NativeBridge.ensureLoaded()
            return NativeBridge.nativeVerifyConfigSignature(config, signature, publicKey) == 1
        }
    }
}

/** Raised when an FFI call returns a failure status. */
internal class TrustCoreException(message: String) : RuntimeException(message)

/**
 * Real trust core backed by the Rust `kseal-ffi` C ABI over JNI.
 *
 * Owns an opaque core handle for its lifetime; [close] releases it. Instances
 * are safe to share across threads (the underlying core is immutable after
 * config load and the FFI takes a shared reference for read paths).
 */
internal class NativeTrustCore private constructor(
    private val handle: Long,
) : TrustCore {

    @Volatile
    private var closed = false

    override val version: String
        get() = NativeBridge.nativeVersion()

    override fun loadConfig(signedConfigBytes: ByteArray) {
        check(!closed) { "core is closed" }
        val status = NativeBridge.nativeLoadConfig(handle, signedConfigBytes)
        if (status != STATUS_OK) {
            throw TrustCoreException("loadConfig failed: status=$status")
        }
    }

    override fun tryLoadConfig(signedConfigBytes: ByteArray): Boolean {
        check(!closed) { "core is closed" }
        return NativeBridge.nativeLoadConfig(handle, signedConfigBytes) == STATUS_OK
    }

    override fun evaluateRisk(riskBits: Long): CoreRiskScore {
        check(!closed) { "core is closed" }
        val out = NativeBridge.nativeEvaluateRisk(handle, riskBits)
        if (out.size != 2) throw TrustCoreException("evaluateRisk returned malformed result")
        return CoreRiskScore(out[0], Confidence.fromCode(out[1]))
    }

    override fun computeRiskLevel(riskBits: Long): TrustLevel {
        check(!closed) { "core is closed" }
        val code = NativeBridge.nativeComputeRiskLevel(handle, riskBits)
        if (code < 0) throw TrustCoreException("computeRiskLevel failed: status=$code")
        return TrustLevel.fromCode(code)
    }

    override fun createEvent(
        eventType: EventType,
        riskBits: Long,
        confidence: Confidence,
        buildHash: String,
        policyHash: String,
        installKeyHash: String,
        coarseTimeBucket: Long,
        country: String?,
    ): ByteArray {
        check(!closed) { "core is closed" }
        return NativeBridge.nativeCreateEvent(
            handle,
            eventType.code,
            riskBits,
            confidence.code,
            buildHash,
            policyHash,
            installKeyHash,
            coarseTimeBucket,
            country,
        ) ?: throw TrustCoreException("createEvent failed")
    }

    override fun batchAndCompress(events: List<ByteArray>): ByteArray {
        check(!closed) { "core is closed" }
        return NativeBridge.nativeBatchAndCompress(handle, events.toTypedArray())
            ?: throw TrustCoreException("batchAndCompress failed")
    }

    override fun generateRequestProof(
        tokenId: String,
        requestHash: ByteArray,
        nonce: ByteArray,
        sequence: Long,
    ): ByteArray {
        check(!closed) { "core is closed" }
        return NativeBridge.nativeGenerateRequestProof(handle, tokenId, requestHash, nonce, sequence)
            ?: throw TrustCoreException("generateRequestProof failed")
    }

    override fun generateNonce(length: Int): ByteArray {
        return NativeBridge.nativeGenerateNonce(length)
            ?: throw TrustCoreException("generateNonce failed")
    }

    override fun compress(data: ByteArray, level: Int): ByteArray {
        return NativeBridge.nativeCompress(data, level)
            ?: throw TrustCoreException("compress failed")
    }

    override fun decompress(data: ByteArray): ByteArray {
        return NativeBridge.nativeDecompress(data)
            ?: throw TrustCoreException("decompress failed")
    }

    override fun close() {
        if (!closed) {
            closed = true
            NativeBridge.nativeCoreFree(handle)
        }
    }

    companion object {
        private const val STATUS_OK = 0

        /**
         * Creates a core instance.
         *
         * @param configPublicKey Ed25519 public key (32 bytes) used to verify signed configs.
         * @param proofKey instance HMAC key for request proofs (hardware-bound in production).
         * @param maxBatchEvents 0 selects the core default (64).
         * @param riskWindow 0 selects the core default.
         * @param zstdLevel 0 selects the core default.
         */
        fun create(
            configPublicKey: ByteArray,
            proofKey: ByteArray,
            platform: Platform = Platform.ANDROID,
            maxBatchEvents: Int = 0,
            riskWindow: Int = 0,
            zstdLevel: Int = 0,
        ): NativeTrustCore {
            NativeBridge.ensureLoaded()
            val handle = NativeBridge.nativeCoreNew(
                configPublicKey,
                proofKey,
                platform.code,
                maxBatchEvents,
                riskWindow,
                zstdLevel,
            )
            if (handle == 0L) {
                throw TrustCoreException("failed to create trust core (bad key arguments?)")
            }
            return NativeTrustCore(handle)
        }
    }
}
