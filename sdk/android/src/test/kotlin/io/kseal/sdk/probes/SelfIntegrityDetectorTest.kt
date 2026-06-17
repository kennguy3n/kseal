package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelfIntegrityDetectorTest {

    private val codePath = "/data/app/base/lib/arm64-v8a/libapp.so"
    private val artifactPath = "/data/app/base.apk"
    private val baseline = "ab".repeat(32)

    @Test
    fun emptyPolicyIsSilent() {
        val env = FakeDeviceEnvironment().apply {
            fileDigests[codePath] = "cd".repeat(32)
            fileDigests[artifactPath] = "cd".repeat(32)
        }
        assertTrue(SelfIntegrityDetector(env, TamperPolicy()).evaluate().isEmpty())
    }

    @Test
    fun matchingCodeDigestIsClean() {
        val env = FakeDeviceEnvironment().apply { fileDigests[codePath] = baseline }
        val policy = TamperPolicy(expectedCodeSha256 = mapOf(codePath to baseline))
        assertTrue(SelfIntegrityDetector(env, policy).evaluate().isEmpty())
    }

    @Test
    fun caseInsensitiveCodeDigestIsClean() {
        val env = FakeDeviceEnvironment().apply { fileDigests[codePath] = baseline.uppercase() }
        val policy = TamperPolicy(expectedCodeSha256 = mapOf(codePath to baseline))
        assertTrue(SelfIntegrityDetector(env, policy).evaluate().isEmpty())
    }

    @Test
    fun mismatchedCodeDigestRaisesTamper() {
        val env = FakeDeviceEnvironment().apply { fileDigests[codePath] = "cd".repeat(32) }
        val policy = TamperPolicy(expectedCodeSha256 = mapOf(codePath to baseline))
        assertEquals(setOf(RiskSignal.TAMPER), SelfIntegrityDetector(env, policy).evaluate())
    }

    @Test
    fun mismatchedArtifactDigestRaisesAppIntegrity() {
        val env = FakeDeviceEnvironment().apply { fileDigests[artifactPath] = "cd".repeat(32) }
        val policy = TamperPolicy(expectedArtifactSha256 = mapOf(artifactPath to baseline))
        assertEquals(setOf(RiskSignal.APP_INTEGRITY), SelfIntegrityDetector(env, policy).evaluate())
    }

    @Test
    fun bothMismatchesRaiseBothSignals() {
        val env = FakeDeviceEnvironment().apply {
            fileDigests[codePath] = "cd".repeat(32)
            fileDigests[artifactPath] = "cd".repeat(32)
        }
        val policy = TamperPolicy(
            expectedCodeSha256 = mapOf(codePath to baseline),
            expectedArtifactSha256 = mapOf(artifactPath to baseline),
        )
        assertEquals(
            setOf(RiskSignal.TAMPER, RiskSignal.APP_INTEGRITY),
            SelfIntegrityDetector(env, policy).evaluate(),
        )
    }

    @Test
    fun unmeasurableFileIsSilent() {
        // No digest registered for the path => sha256OfFile returns null => the
        // baseline is configured but the file cannot be measured, so the
        // fail-safe contract contributes no signal.
        val env = FakeDeviceEnvironment()
        val policy = TamperPolicy(
            expectedCodeSha256 = mapOf(codePath to baseline),
            expectedArtifactSha256 = mapOf(artifactPath to baseline),
        )
        assertTrue(SelfIntegrityDetector(env, policy).evaluate().isEmpty())
    }

    @Test
    fun failClosedRaisesTamperForUnmeasurableCode() {
        // Opt-in fail-closed: an unmeasurable baseline-registered code file is
        // treated as a mismatch instead of being skipped.
        val env = FakeDeviceEnvironment()
        val policy = TamperPolicy(
            expectedCodeSha256 = mapOf(codePath to baseline),
            failClosedOnUnmeasurable = true,
        )
        assertEquals(setOf(RiskSignal.TAMPER), SelfIntegrityDetector(env, policy).evaluate())
    }

    @Test
    fun failClosedRaisesAppIntegrityForUnmeasurableArtifact() {
        val env = FakeDeviceEnvironment()
        val policy = TamperPolicy(
            expectedArtifactSha256 = mapOf(artifactPath to baseline),
            failClosedOnUnmeasurable = true,
        )
        assertEquals(
            setOf(RiskSignal.APP_INTEGRITY),
            SelfIntegrityDetector(env, policy).evaluate(),
        )
    }

    @Test
    fun failClosedStillCleanWhenMeasurableAndMatching() {
        // The flag must not turn a measurable, matching file into a signal.
        val env = FakeDeviceEnvironment().apply { fileDigests[codePath] = baseline }
        val policy = TamperPolicy(
            expectedCodeSha256 = mapOf(codePath to baseline),
            failClosedOnUnmeasurable = true,
        )
        assertTrue(SelfIntegrityDetector(env, policy).evaluate().isEmpty())
    }
}
