package io.kseal.sdk.internal

/**
 * Thin JNI declaration layer over the Rust trust core's C ABI (`kseal.h`).
 *
 * Every method maps 1:1 to a `kseal_*` export. The implementation lives in
 * `src/main/jni/kseal_jni.c`, compiled by the NDK into `libkseal_jni.so` (which
 * links the prebuilt `libkseal_ffi.so`). The same C source is compiled for the
 * host JDK in unit tests, so these bindings are exercised against the real core
 * on the JVM as well as on-device.
 *
 * Methods that can fail return `null` (for byte/array results) or a negative
 * status; the higher-level [NativeTrustCore] converts these into exceptions.
 */
internal object NativeBridge {

    @Volatile
    private var loaded = false

    @Volatile
    private var loadError: Throwable? = null

    init {
        try {
            System.loadLibrary("kseal_jni")
            loaded = true
        } catch (t: UnsatisfiedLinkError) {
            loadError = t
        }
    }

    /** Whether the native trust core library loaded successfully. */
    val isAvailable: Boolean get() = loaded

    /** Throws a descriptive error if the native library is unavailable. */
    fun ensureLoaded() {
        if (!loaded) {
            throw IllegalStateException(
                "kseal native trust core (libkseal_jni.so) is not loaded. " +
                    "On device it ships in the AAR; for JVM tests build it via " +
                    "scripts/build-host-jni.sh and set -Djava.library.path.",
                loadError,
            )
        }
    }

    external fun nativeVersion(): String

    external fun nativeCoreNew(
        configPublicKey: ByteArray,
        proofKey: ByteArray,
        platform: Int,
        maxBatchEvents: Int,
        riskWindow: Int,
        zstdLevel: Int,
    ): Long

    external fun nativeCoreFree(handle: Long)

    /** Returns a `KsealStatus` (0 = Ok, negative = error). */
    external fun nativeLoadConfig(handle: Long, bytes: ByteArray): Int

    /** Returns `[score, confidence]` (score widened from u32), or `null` on error. */
    external fun nativeEvaluateRisk(handle: Long, riskBits: Long): LongArray?

    /** Returns the `TrustLevel` discriminant, or a negative status on error. */
    external fun nativeComputeRiskLevel(handle: Long, riskBits: Long): Int

    /** Returns serialized `TelemetryEvent` bytes, or `null` on error. */
    external fun nativeCreateEvent(
        handle: Long,
        eventType: Int,
        riskBits: Long,
        confidence: Int,
        buildHash: String,
        policyHash: String,
        installKeyHash: String,
        coarseTimeBucket: Long,
        country: String?,
    ): ByteArray?

    /** Returns the compressed protobuf wire batch, or `null` on error. */
    external fun nativeBatchAndCompress(handle: Long, events: Array<ByteArray>): ByteArray?

    /** Returns serialized `RequestProof` bytes, or `null` on error. */
    external fun nativeGenerateRequestProof(
        handle: Long,
        tokenId: String,
        requestHash: ByteArray,
        nonce: ByteArray,
        seq: Long,
    ): ByteArray?

    /** Returns 1 (valid), 0 (invalid), or a negative status on bad args. */
    external fun nativeVerifyConfigSignature(
        config: ByteArray,
        signature: ByteArray,
        publicKey: ByteArray,
    ): Int

    external fun nativeCompress(data: ByteArray, level: Int): ByteArray?

    external fun nativeDecompress(data: ByteArray): ByteArray?

    external fun nativeGenerateNonce(len: Int): ByteArray?
}
