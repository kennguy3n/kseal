package io.kseal.sdk.internal

import io.kseal.sdk.Confidence
import io.kseal.sdk.EventType
import io.kseal.sdk.KsealErrorCode
import io.kseal.sdk.KsealException
import io.kseal.sdk.Platform
import io.kseal.sdk.TrustLevel
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/** Weighted risk score plus the confidence the core derived for it.
 *
 * [score] is a `Long` holding the core's unsigned 32-bit score (0..u32::MAX)
 * without the negative wrap a signed 32-bit type would suffer at the boundary. */
internal data class CoreRiskScore(val score: Long, val confidence: Confidence)

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

    /**
     * Scores [riskBits] and derives the trust level in a single critical section,
     * so a concurrent config swap cannot land between the two and yield a score
     * and level computed against different policies.
     */
    fun evaluateRiskAndLevel(riskBits: Long): Pair<CoreRiskScore, TrustLevel>

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

/**
 * Raised when an FFI call returns a failure status. A [KsealException] so callers
 * can catch the whole SDK error family and branch on [KsealException.code]; the
 * message-only constructor defaults to [KsealErrorCode.INTERNAL_ERROR] for the
 * JNI paths that collapse a granular status into a null result.
 */
internal class TrustCoreException : KsealException {
    constructor(message: String) : super(KsealErrorCode.INTERNAL_ERROR, message)
    constructor(code: KsealErrorCode, message: String) : super(code, message)
}

/**
 * Real trust core backed by the Rust `kseal-ffi` C ABI over JNI.
 *
 * Owns an opaque core handle for its lifetime; [close] releases it.
 *
 * Thread-safety mirrors the Rust borrow semantics of the C ABI: config mutation
 * (`kseal_load_config` takes `&mut`) is serialized under the write lock, while
 * the read paths (`&self`: risk evaluation, event/proof creation) run under the
 * shared read lock and may proceed concurrently. [close] takes the write lock
 * and frees the handle exactly once, so concurrent closes cannot double-free.
 * `generateNonce`/`compress`/`decompress` are stateless (no core handle) and
 * need no locking.
 */
internal class NativeTrustCore private constructor(
    private val handle: Long,
) : TrustCore {

    private val coreLock = ReentrantReadWriteLock()

    @Volatile
    private var closed = false

    override val version: String
        get() = NativeBridge.nativeVersion()

    override fun loadConfig(signedConfigBytes: ByteArray): Unit = coreLock.write {
        check(!closed) { "core is closed" }
        val status = NativeBridge.nativeLoadConfig(handle, signedConfigBytes)
        if (status != STATUS_OK) {
            throw TrustCoreException(KsealErrorCode.CONFIG_REJECTED, "loadConfig failed: status=$status")
        }
    }

    override fun tryLoadConfig(signedConfigBytes: ByteArray): Boolean = coreLock.write {
        check(!closed) { "core is closed" }
        NativeBridge.nativeLoadConfig(handle, signedConfigBytes) == STATUS_OK
    }

    override fun evaluateRisk(riskBits: Long): CoreRiskScore = coreLock.read {
        check(!closed) { "core is closed" }
        val out = NativeBridge.nativeEvaluateRisk(handle, riskBits)
            ?: throw TrustCoreException("evaluateRisk failed")
        if (out.size != 2) throw TrustCoreException("evaluateRisk returned malformed result")
        CoreRiskScore(out[0], Confidence.fromCode(out[1].toInt()))
    }

    override fun computeRiskLevel(riskBits: Long): TrustLevel = coreLock.read {
        check(!closed) { "core is closed" }
        val code = NativeBridge.nativeComputeRiskLevel(handle, riskBits)
        if (code < 0) throw TrustCoreException("computeRiskLevel failed: status=$code")
        TrustLevel.fromCode(code)
    }

    // The read lock is reentrant, so holding it across both calls keeps them
    // atomic w.r.t. a writer (loadConfig) without duplicating their bodies.
    override fun evaluateRiskAndLevel(riskBits: Long): Pair<CoreRiskScore, TrustLevel> =
        coreLock.read { evaluateRisk(riskBits) to computeRiskLevel(riskBits) }

    override fun createEvent(
        eventType: EventType,
        riskBits: Long,
        confidence: Confidence,
        buildHash: String,
        policyHash: String,
        installKeyHash: String,
        coarseTimeBucket: Long,
        country: String?,
    ): ByteArray = coreLock.read {
        check(!closed) { "core is closed" }
        NativeBridge.nativeCreateEvent(
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

    override fun batchAndCompress(events: List<ByteArray>): ByteArray = coreLock.read {
        check(!closed) { "core is closed" }
        NativeBridge.nativeBatchAndCompress(handle, events.toTypedArray())
            ?: throw TrustCoreException("batchAndCompress failed")
    }

    override fun generateRequestProof(
        tokenId: String,
        requestHash: ByteArray,
        nonce: ByteArray,
        sequence: Long,
    ): ByteArray = coreLock.read {
        check(!closed) { "core is closed" }
        NativeBridge.nativeGenerateRequestProof(handle, tokenId, requestHash, nonce, sequence)
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

    override fun close() = coreLock.write {
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
                throw TrustCoreException(KsealErrorCode.CORE_INITIALIZATION_FAILED, "failed to create trust core (bad key arguments?)")
            }
            return NativeTrustCore(handle)
        }
    }
}
