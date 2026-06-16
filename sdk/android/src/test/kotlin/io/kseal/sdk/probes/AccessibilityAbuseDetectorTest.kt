package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AccessibilityAbuseDetectorTest {

    @Test
    fun cleanDeviceReportsNoSignals() {
        val env = FakeDeviceEnvironment()
        assertTrue(AccessibilityAbuseDetector(env).evaluate().isEmpty())
    }

    @Test
    fun thirdPartyServiceIsAccessibilityAbuse() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf("com.evil.spy/com.evil.spy.HijackService")
        assertEquals(
            setOf(RiskSignal.ACCESSIBILITY_ABUSE),
            AccessibilityAbuseDetector(env).evaluate(),
        )
    }

    @Test
    fun talkBackScreenReaderIsBenign() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf(
            "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService",
        )
        assertTrue(AccessibilityAbuseDetector(env).evaluate().isEmpty())
    }

    @Test
    fun androidSystemAccessibilityServiceIsBenign() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf(
            "com.android.settings/com.android.settings.accessibility.SomeService",
        )
        assertTrue(AccessibilityAbuseDetector(env).evaluate().isEmpty())
    }

    @Test
    fun samsungOemAccessibilityServiceIsBenign() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf(
            "com.samsung.accessibility/com.samsung.accessibility.universalswitch.UniversalSwitchService",
        )
        assertTrue(AccessibilityAbuseDetector(env).evaluate().isEmpty())
    }

    @Test
    fun xiaomiMiuiOemAccessibilityServiceIsBenign() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf(
            "com.miui.accessibility/com.miui.accessibility.asr.SomeService",
        )
        assertTrue(AccessibilityAbuseDetector(env).evaluate().isEmpty())
    }

    @Test
    fun otherMajorOemAccessibilityServicesAreBenign() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf(
            "com.huawei.accessibility/com.huawei.accessibility.SomeService",
            "com.oneplus.accessibility/com.oneplus.accessibility.SomeService",
            "com.coloros.accessibility/com.coloros.accessibility.SomeService",
            "com.vivo.accessibility/com.vivo.accessibility.SomeService",
        )
        assertTrue(AccessibilityAbuseDetector(env).evaluate().isEmpty())
    }

    @Test
    fun bareAndroidFrameworkPackageIsBenign() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf("android/android.SomeFrameworkService")
        assertTrue(AccessibilityAbuseDetector(env).evaluate().isEmpty())
    }

    @Test
    fun mixedSystemAndThirdPartyServicesFlagsAbuse() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf(
            "com.google.android.marvin.talkback/com.google.android.marvin.talkback.TalkBackService",
            "com.unknown.rat/com.unknown.rat.RemoteService",
        )
        assertTrue(RiskSignal.ACCESSIBILITY_ABUSE in AccessibilityAbuseDetector(env).evaluate())
    }

    @Test
    fun blankEntriesAreIgnored() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf("", "   ")
        assertTrue(AccessibilityAbuseDetector(env).evaluate().isEmpty())
    }

    @Test
    fun componentNameWithoutClassSeparatorIsClassifiedByPackage() {
        val env = FakeDeviceEnvironment()
        env.accessibilityServices = listOf("com.evil.spy")
        assertEquals(
            setOf(RiskSignal.ACCESSIBILITY_ABUSE),
            AccessibilityAbuseDetector(env).evaluate(),
        )
    }
}
