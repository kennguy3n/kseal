package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IntegrityCheckerTest {

    private val goodCert = "ab".repeat(32)

    @Test
    fun matchingSigningCertIsClean() {
        val env = FakeDeviceEnvironment().apply { signingCerts = listOf(goodCert) }
        val policy = IntegrityPolicy(expectedSigningCertSha256 = setOf(goodCert))
        assertTrue(IntegrityChecker(env, policy).evaluate().isEmpty())
    }

    @Test
    fun mismatchedSigningCertIsRepackaged() {
        val env = FakeDeviceEnvironment().apply { signingCerts = listOf("cd".repeat(32)) }
        val policy = IntegrityPolicy(expectedSigningCertSha256 = setOf(goodCert))
        val signals = IntegrityChecker(env, policy).evaluate()
        assertTrue(RiskSignal.REPACKAGED in signals)
        assertTrue(RiskSignal.APP_INTEGRITY in signals)
    }

    @Test
    fun caseInsensitiveCertMatch() {
        val env = FakeDeviceEnvironment().apply { signingCerts = listOf(goodCert.uppercase()) }
        val policy = IntegrityPolicy(expectedSigningCertSha256 = setOf(goodCert))
        assertTrue(IntegrityChecker(env, policy).evaluate().isEmpty())
    }

    @Test
    fun noBaselineSkipsCertCheck() {
        val env = FakeDeviceEnvironment().apply { signingCerts = listOf("cd".repeat(32)) }
        assertTrue(IntegrityChecker(env, IntegrityPolicy()).evaluate().isEmpty())
    }

    @Test
    fun unknownInstallerFlaggedWhenRequired() {
        val env = FakeDeviceEnvironment().apply { installer = "com.sideload.tool" }
        val policy = IntegrityPolicy(requireKnownInstaller = true)
        assertTrue(RiskSignal.APP_INTEGRITY in IntegrityChecker(env, policy).evaluate())
    }

    @Test
    fun playStoreInstallerIsClean() {
        val env = FakeDeviceEnvironment().apply { installer = "com.android.vending" }
        val policy = IntegrityPolicy(requireKnownInstaller = true)
        assertFalse(RiskSignal.APP_INTEGRITY in IntegrityChecker(env, policy).evaluate())
    }

    @Test
    fun nullInstallerFlaggedWhenRequired() {
        val env = FakeDeviceEnvironment().apply { installer = null }
        val policy = IntegrityPolicy(requireKnownInstaller = true)
        assertTrue(RiskSignal.APP_INTEGRITY in IntegrityChecker(env, policy).evaluate())
    }
}
