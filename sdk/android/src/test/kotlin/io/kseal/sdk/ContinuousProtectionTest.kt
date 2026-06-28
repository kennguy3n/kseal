package io.kseal.sdk

import io.kseal.sdk.internal.CoreRiskScore
import io.kseal.sdk.internal.TrustCore
import io.kseal.sdk.probes.FakeDeviceEnvironment
import io.kseal.sdk.probes.IntegrityPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Phase 3 continuous-protection / active-response wiring, driven against a
 * [FakeTrustCore] so the scheduler, [KsealSDK.onTrustDecision] dispatch, and
 * kill-switch surfacing are exercised deterministically without the native
 * library or Ed25519 signing. The authoritative crypto / decision / kill-switch
 * semantics are pinned by the Rust core + FFI tests (which run in CI).
 */
class ContinuousProtectionTest {

    /** A scriptable [TrustCore] with no native dependency. */
    private class FakeTrustCore(
        var intervalSecs: Long = 0,
        var level: TrustLevel = TrustLevel.TRUSTED,
        var decisionValue: Decision = Decision.ALLOW,
    ) : TrustCore {
        var killed: Boolean = false
        var applyResult: Boolean = false
        var loadConfigCount: Int = 0

        override val version: String = "fake-core"
        override fun loadConfig(signedConfigBytes: ByteArray) {}
        override fun tryLoadConfig(signedConfigBytes: ByteArray): Boolean {
            loadConfigCount++
            return true
        }
        override fun evaluateRisk(riskBits: Long) = CoreRiskScore(riskBits, Confidence.HIGH)
        override fun computeRiskLevel(riskBits: Long) = level
        override fun evaluateRiskAndLevel(riskBits: Long) =
            CoreRiskScore(riskBits, Confidence.HIGH) to level
        override fun createEvent(
            eventType: EventType,
            riskBits: Long,
            confidence: Confidence,
            buildHash: String,
            policyHash: String,
            installKeyHash: String,
            coarseTimeBucket: Long,
            country: String?,
        ) = ByteArray(0)
        override fun batchAndCompress(events: List<ByteArray>) = ByteArray(0)
        override fun generateRequestProof(
            tokenId: String,
            requestHash: ByteArray,
            nonce: ByteArray,
            sequence: Long,
        ) = ByteArray(0)
        override fun generateNonce(length: Int) = ByteArray(length)
        override fun compress(data: ByteArray, level: Int) = data
        override fun decompress(data: ByteArray) = data
        override fun reattestIntervalSecs() = intervalSecs
        override fun decision(riskBits: Long) = decisionValue
        override fun decisionWithLevel(riskBits: Long) = level to decisionValue
        override fun applyKillSwitch(signedKillSwitchBytes: ByteArray): Boolean {
            killed = applyResult
            return killed
        }
        override fun isKilled() = killed
        override fun close() {}
    }

    /** Records fetch calls so escalation can be observed. */
    private class CountingConfigProvider(
        private val config: ByteArray? = ByteArray(4),
        private val killSwitch: ByteArray? = null,
    ) : ConfigProvider {
        var fetchConfigCount: Int = 0
        var fetchKillSwitchCount: Int = 0
        override fun cachedConfig(): ByteArray? = config
        override fun fetchConfig(): ByteArray? {
            fetchConfigCount++
            return config
        }
        override fun persist(config: ByteArray) {}
        override fun fetchKillSwitch(): ByteArray? {
            fetchKillSwitchCount++
            return killSwitch
        }
    }

    private fun newSdk(
        core: FakeTrustCore,
        configProvider: ConfigProvider = CountingConfigProvider(),
    ): KsealSDK = KsealSDK(
        tenantId = "tenant-a",
        appId = "com.example.app",
        apiKey = "api-key",
        core = core,
        env = FakeDeviceEnvironment(),
        options = KsealOptions(buildHash = "bh", integrityPolicy = IntegrityPolicy()),
        configProvider = configProvider,
        telemetrySink = BufferingTelemetrySink(),
        installIdentityHash = "install-hash",
        clock = { 1_700_000_000_000L },
    )

    @Test
    fun continuousModeOffByDefault() {
        val core = FakeTrustCore(intervalSecs = 0)
        val sdk = newSdk(core)
        assertEquals(0L, sdk.reattestIntervalSecs)
        // Opting in is a no-op when the policy did not enable continuous mode.
        assertFalse(sdk.startContinuousProtection())
    }

    @Test
    fun reattestCycleDispatchesTrustDecision() {
        val core = FakeTrustCore(level = TrustLevel.HIGH_RISK, decisionValue = Decision.DENY)
        val sdk = newSdk(core)
        var seen: Pair<TrustLevel, Decision>? = null
        sdk.onTrustDecision = { level, decision -> seen = level to decision }

        sdk.runReattestCycle()

        assertEquals(TrustLevel.HIGH_RISK to Decision.DENY, seen)
    }

    @Test
    fun stepUpDecisionIsSurfaced() {
        val core = FakeTrustCore(level = TrustLevel.MEDIUM_RISK, decisionValue = Decision.STEP_UP)
        val sdk = newSdk(core)
        val (level, decision) = sdk.evaluateTrustDecision()
        assertEquals(TrustLevel.MEDIUM_RISK, level)
        assertEquals(Decision.STEP_UP, decision)
    }

    @Test
    fun reattestCycleAlwaysPullsKillSwitch() {
        // Kill switch is always pulled regardless of risk level.
        val trusted = FakeTrustCore(level = TrustLevel.TRUSTED, decisionValue = Decision.ALLOW)
        val trustedProvider = CountingConfigProvider()
        newSdk(trusted, trustedProvider).runReattestCycle()
        assertEquals(1, trustedProvider.fetchKillSwitchCount)

        // Elevated risk: kill switch is also pulled and applied.
        val risky = FakeTrustCore(level = TrustLevel.HIGH_RISK, decisionValue = Decision.DENY)
        val riskyProvider = CountingConfigProvider(killSwitch = ByteArray(8))
        newSdk(risky, riskyProvider).runReattestCycle()
        assertEquals(1, riskyProvider.fetchKillSwitchCount)
    }

    @Test
    fun killSwitchSurfacingFiresOnTransition() {
        val core = FakeTrustCore()
        core.applyResult = true
        val sdk = newSdk(core)
        var lastState: Boolean? = null
        sdk.onKillSwitchChanged = { lastState = it }

        assertFalse(sdk.isKilled)
        val killed = sdk.applyKillSwitch(ByteArray(16))

        assertTrue(killed)
        assertTrue(sdk.isKilled)
        assertEquals(true, lastState)
    }

    @Test
    fun killSwitchListenerNotFiredWithoutTransition() {
        val core = FakeTrustCore()
        core.applyResult = false
        val sdk = newSdk(core)
        var fired = false
        sdk.onKillSwitchChanged = { fired = true }

        assertFalse(sdk.applyKillSwitch(ByteArray(16)))
        assertFalse(fired)
        assertFalse(sdk.isKilled)
    }

    @Test
    fun refreshKillSwitchIsNoOpWhenProviderHasNone() {
        val core = FakeTrustCore()
        val provider = CountingConfigProvider(killSwitch = null)
        val sdk = newSdk(core, provider)
        var fired = false
        sdk.onKillSwitchChanged = { fired = true }

        assertFalse(sdk.refreshKillSwitch())
        assertEquals(1, provider.fetchKillSwitchCount)
        assertFalse(fired)
    }

    @Test
    fun defaultTrustDecisionListenerIsNoOp() {
        val core = FakeTrustCore(level = TrustLevel.CRITICAL, decisionValue = Decision.DENY)
        val sdk = newSdk(core)
        // No listener registered: the cycle must complete without throwing and
        // never act on the decision itself.
        assertNull(sdk.onTrustDecision)
        sdk.runReattestCycle()
    }
}
