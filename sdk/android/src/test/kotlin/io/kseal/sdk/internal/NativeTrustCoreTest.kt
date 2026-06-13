package io.kseal.sdk.internal

import io.kseal.sdk.Confidence
import io.kseal.sdk.EventType
import io.kseal.sdk.Platform
import io.kseal.sdk.RiskSignal
import io.kseal.sdk.TrustLevel
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test

/**
 * Exercises the REAL Rust trust core through the REAL JNI bridge on the JVM.
 *
 * The library (`libkseal_jni.so`, statically linking `libkseal_ffi.a`) is built
 * by `scripts/build-host-jni.sh` and put on `java.library.path` by the Gradle
 * `test` task. This is not a mock — it is the same `kseal_*` C ABI the Android
 * AAR ships, validating the FFI integration end to end.
 */
class NativeTrustCoreTest {

    companion object {
        @JvmStatic
        @BeforeClass
        fun requireNative() {
            assertTrue(
                "native trust core not loaded; run via ./gradlew test (builds host JNI)",
                NativeBridge.isAvailable,
            )
        }
    }

    private lateinit var core: NativeTrustCore

    @Before
    fun setUp() {
        core = NativeTrustCore.create(
            configPublicKey = ByteArray(32) { 7 },
            proofKey = "instance-key".toByteArray(),
            platform = Platform.ANDROID,
        )
    }

    @Test
    fun versionIsNonEmpty() {
        assertTrue(core.version.isNotEmpty())
    }

    @Test
    fun nonceHasRequestedLength() {
        val nonce = core.generateNonce(16)
        assertEquals(16, nonce.size)
        // Two nonces must differ (cryptographically random).
        assertFalse(nonce.contentEquals(core.generateNonce(16)))
    }

    @Test
    fun compressDecompressRoundTrips() {
        val data = "kseal ".repeat(64).toByteArray()
        val compressed = core.compress(data)
        assertTrue(compressed.isNotEmpty())
        assertArrayEquals(data, core.decompress(compressed))
    }

    /** With no policy loaded the core uses the default per-signal weight (10). */
    @Test
    fun evaluateRiskUsesDefaultWeightsWithoutPolicy() {
        val bits = RiskSignal.pack(setOf(RiskSignal.ROOT, RiskSignal.DEBUGGER))
        val score = core.evaluateRisk(bits)
        assertEquals(20L, score.score)
        // Two distinct signals → medium confidence per the core's derivation.
        assertEquals(Confidence.MEDIUM, score.confidence)
    }

    @Test
    fun cleanBitsScoreZero() {
        val score = core.evaluateRisk(0L)
        assertEquals(0L, score.score)
        assertEquals(Confidence.HIGH, score.confidence)
    }

    /** Trust level requires policy thresholds; without a policy it is UNSPECIFIED. */
    @Test
    fun trustLevelUnspecifiedWithoutPolicy() {
        val bits = RiskSignal.pack(setOf(RiskSignal.ROOT))
        assertEquals(TrustLevel.UNSPECIFIED, core.computeRiskLevel(bits))
    }

    @Test
    fun createEventAndBatchProduceWire() {
        val event = core.createEvent(
            eventType = EventType.ROOT_RISK,
            riskBits = RiskSignal.ROOT.mask,
            confidence = Confidence.LOW,
            buildHash = "build",
            policyHash = "policy",
            installKeyHash = "install",
            coarseTimeBucket = 1_700_000_000L,
            country = null,
        )
        assertTrue(event.isNotEmpty())
        val wire = core.batchAndCompress(listOf(event))
        assertTrue(wire.isNotEmpty())
    }

    @Test
    fun requestProofIsDeterministicForSameInputs() {
        val hash = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(16) { 9 }
        val p1 = core.generateRequestProof("tok-1", hash, nonce, 7)
        val p2 = core.generateRequestProof("tok-1", hash, nonce, 7)
        assertTrue(p1.isNotEmpty())
        assertArrayEquals(p1, p2)
        // A different sequence number yields a different proof.
        val p3 = core.generateRequestProof("tok-1", hash, nonce, 8)
        assertFalse(p1.contentEquals(p3))
    }

    @Test
    fun verifyConfigSignatureRejectsGarbage() {
        val verified = TrustCore.verifyConfigSignature(
            config = "config".toByteArray(),
            signature = ByteArray(64),
            publicKey = ByteArray(32) { 7 },
        )
        assertFalse(verified)
    }

    @Test
    fun loadingGarbageConfigFailsGracefully() {
        assertFalse(core.tryLoadConfig(byteArrayOf(1, 2, 3, 4)))
    }

    @Test
    fun createInstanceIsNotNull() {
        assertNotNull(core)
    }
}
