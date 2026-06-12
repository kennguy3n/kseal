package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootDetectorTest {

    @Test
    fun cleanDeviceReportsNoSignals() {
        val env = FakeDeviceEnvironment()
        assertTrue(RootDetector(env).evaluate().isEmpty())
    }

    @Test
    fun suBinaryOnPathIsRoot() {
        val env = FakeDeviceEnvironment()
        env.executableFiles += "/system/xbin/su"
        assertTrue(RiskSignal.ROOT in RootDetector(env).evaluate())
    }

    @Test
    fun suOnSearchPathIsRoot() {
        val env = FakeDeviceEnvironment()
        env.pathDirs = listOf("/sbin")
        env.executableFiles += "/sbin/su"
        assertTrue(RiskSignal.ROOT in RootDetector(env).evaluate())
    }

    @Test
    fun magiskArtifactIsRoot() {
        val env = FakeDeviceEnvironment()
        env.existingFiles += "/data/adb/magisk"
        assertTrue(RiskSignal.ROOT in RootDetector(env).evaluate())
    }

    @Test
    fun rootPackageIsRoot() {
        val env = FakeDeviceEnvironment()
        env.packages = env.packages + "com.topjohnwu.magisk"
        assertTrue(RiskSignal.ROOT in RootDetector(env).evaluate())
    }

    @Test
    fun permissiveSelinuxIsEnvironmentRisk() {
        val env = FakeDeviceEnvironment()
        env.textFiles["/sys/fs/selinux/enforce"] = "0\n"
        val signals = RootDetector(env).evaluate()
        assertTrue(RiskSignal.ENVIRONMENT in signals)
        assertFalse(RiskSignal.ROOT in signals)
    }

    @Test
    fun testKeysBuildIsEnvironmentRisk() {
        val env = FakeDeviceEnvironment(buildTags = "test-keys")
        assertTrue(RiskSignal.ENVIRONMENT in RootDetector(env).evaluate())
    }

    @Test
    fun debuggableBuildIsEnvironmentRisk() {
        val env = FakeDeviceEnvironment()
        env.systemProperties["ro.debuggable"] = "1"
        assertEquals(setOf(RiskSignal.ENVIRONMENT), RootDetector(env).evaluate())
    }
}
