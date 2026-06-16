package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OverlayDetectorTest {

    @Test
    fun noOverlayAppsIsClean() {
        assertTrue(OverlayDetector(FakeDeviceEnvironment()).evaluate().isEmpty())
    }

    @Test
    fun thirdPartyOverlayAppIsOverlayAbuse() {
        val env = FakeDeviceEnvironment().apply {
            overlayPackages = listOf("com.evil.tapjacker")
        }
        assertEquals(setOf(RiskSignal.OVERLAY_ABUSE), OverlayDetector(env).evaluate())
    }

    @Test
    fun onlySystemOverlayAppsAreClean() {
        val env = FakeDeviceEnvironment().apply {
            overlayPackages = listOf(
                "android",
                "com.android.systemui",
                "com.google.android.apps.nexuslauncher",
                "com.google.android.marvin.talkback",
                "com.samsung.android.app.cocktailbarservice",
                "com.miui.home",
            )
        }
        assertTrue(OverlayDetector(env).evaluate().isEmpty())
    }

    @Test
    fun thirdPartyAmongSystemAppsIsOverlayAbuse() {
        val env = FakeDeviceEnvironment().apply {
            overlayPackages = listOf(
                "com.android.systemui",
                "com.facebook.katana",
            )
        }
        val signals = OverlayDetector(env).evaluate()
        assertTrue(RiskSignal.OVERLAY_ABUSE in signals)
    }

    @Test
    fun blankPackageNamesAreIgnored() {
        val env = FakeDeviceEnvironment().apply {
            overlayPackages = listOf("", "   ")
        }
        assertTrue(OverlayDetector(env).evaluate().isEmpty())
    }

    @Test
    fun ownHostPackageOverlayIsClean() {
        val env = FakeDeviceEnvironment().apply {
            overlayPackages = listOf("io.kseal.sdk.testhost")
        }
        val signals = OverlayDetector(env).evaluate()
        assertFalse(RiskSignal.OVERLAY_ABUSE in signals)
    }
}
