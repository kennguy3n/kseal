package io.kseal.sdk

import io.kseal.sdk.internal.NativeBridge
import io.kseal.sdk.internal.NativeTrustCore
import io.kseal.sdk.probes.FakeDeviceEnvironment
import io.kseal.sdk.probes.IntegrityPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test

/**
 * End-to-end SDK flow against the REAL Rust trust core (host JNI). Only the
 * device surface is faked ([FakeDeviceEnvironment]) so risk signals are
 * deterministic; the scoring, proof generation, event creation, and telemetry
 * batching all run through the real core.
 */
class KsealSDKFlowTest {

    companion object {
        private const val EXPECTED_CERT = "ab"

        @JvmStatic
        @BeforeClass
        fun requireNative() {
            assertTrue(NativeBridge.isAvailable)
        }
    }

    private lateinit var env: FakeDeviceEnvironment
    private lateinit var sink: BufferingTelemetrySink
    private lateinit var sdk: KsealSDK

    private fun newSdk(maxBatch: Int = 32): KsealSDK {
        val core = NativeTrustCore.create(
            configPublicKey = ByteArray(32) { 3 },
            proofKey = "proof-key".toByteArray(),
            platform = Platform.ANDROID,
        )
        return KsealSDK(
            tenantId = "tenant-a",
            appId = "com.example.app",
            apiKey = "api-key",
            core = core,
            env = env,
            options = KsealOptions(
                buildHash = "buildhash",
                integrityPolicy = IntegrityPolicy(),
                maxBatchEvents = maxBatch,
            ),
            configProvider = NoopConfigProvider,
            telemetrySink = sink,
            installIdentityHash = "install-hash",
            clock = { 1_700_003_600_000L },
        )
    }

    @Before
    fun setUp() {
        env = FakeDeviceEnvironment()
        sink = BufferingTelemetrySink()
        sdk = newSdk()
    }

    @Test
    fun cleanDeviceEvaluatesToNoSignals() {
        val risk = sdk.evaluateRisk()
        assertTrue(risk.isClean)
        assertEquals(0L, risk.riskBits)
        assertEquals(0L, risk.score)
        assertEquals(TrustLevel.UNSPECIFIED, risk.trustLevel)
    }

    @Test
    fun rootedDeviceSurfacesSignalsAndScore() {
        env.executableFiles += "/system/xbin/su"
        env.systemProperties["ro.kernel.qemu"] = "1"
        val risk = sdk.evaluateRisk()
        assertTrue(RiskSignal.ROOT in risk.signals)
        assertTrue(RiskSignal.EMULATOR in risk.signals)
        assertTrue(risk.score > 0)
        // Bits must round-trip through the packed representation.
        assertEquals(risk.signals, RiskSignal.unpack(risk.riskBits))
    }

    @Test
    fun requestProofRequiresTrustToken() {
        assertThrows(IllegalStateException::class.java) {
            sdk.getRequestProof(ByteArray(32))
        }
    }

    @Test
    fun requestProofBindsTokenAndIncrementsSequence() {
        sdk.setTrustToken("token-xyz")
        val hash = ByteArray(32) { it.toByte() }
        val p1 = sdk.getRequestProof(hash)
        val p2 = sdk.getRequestProof(hash)
        assertEquals("token-xyz", p1.tokenId)
        assertEquals(1L, p1.sequence)
        assertEquals(2L, p2.sequence)
        assertTrue(p1.proofBytes.isNotEmpty())
        // Different sequence numbers must produce different proofs.
        assertFalse(p1.proofBytes.contentEquals(p2.proofBytes))
    }

    @Test
    fun reportEventBuffersUntilBatchThreshold() {
        sdk = newSdk(maxBatch = 3)
        sdk.reportEvent(EventType.ROOT_RISK)
        sdk.reportEvent(EventType.DEBUGGER)
        assertTrue("no batch should flush before threshold", sink.drain().isEmpty())
        sdk.reportEvent(EventType.ENVIRONMENT_RISK)
        val batches = sink.drain()
        assertEquals(1, batches.size)
        assertTrue(batches.first().isNotEmpty())
    }

    @Test
    fun flushTelemetryEmitsBufferedEvents() {
        sdk.reportEvent(EventType.POLICY_DECISION)
        sdk.flushTelemetry()
        assertEquals(1, sink.drain().size)
    }

    @Test
    fun flushWithNoEventsEmitsNothing() {
        sdk.flushTelemetry()
        assertTrue(sink.drain().isEmpty())
    }

    @Test
    fun pinningFailureEmitsImmediateEvent() {
        sdk.reportPinningFailure()
        assertEquals(1, sink.drain().size)
    }

    @Test
    fun coreVersionExposed() {
        assertNotNull(sdk.coreVersion)
        assertTrue(sdk.coreVersion.isNotEmpty())
    }

    private object NoopConfigProvider : ConfigProvider {
        override fun cachedConfig(): ByteArray? = null
        override fun fetchConfig(): ByteArray? = null
        override fun persist(config: ByteArray) {}
    }
}
