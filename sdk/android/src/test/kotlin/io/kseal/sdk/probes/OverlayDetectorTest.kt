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
        val systemHolders = listOf(
            "android",
            "com.android.systemui",
            "com.google.android.apps.nexuslauncher",
            "com.google.android.marvin.talkback",
            "com.samsung.android.app.cocktailbarservice",
            "com.miui.home",
            "com.asus.systemui",
        )
        val env = FakeDeviceEnvironment().apply {
            overlayPackages = systemHolders
            systemPackages = systemHolders.toSet()
        }
        assertTrue(OverlayDetector(env).evaluate().isEmpty())
    }

    @Test
    fun thirdPartyAmongSystemAppsIsOverlayAbuse() {
        val env = FakeDeviceEnvironment().apply {
            overlayPackages = listOf("com.android.systemui", "com.facebook.katana")
            systemPackages = setOf("com.android.systemui")
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

    /**
     * Regression guard for the spoofing gap: a user-installed app that adopts an
     * OEM-looking package name is *not* reported as a system app by the OS, so it
     * must still be flagged (trust is keyed off `FLAG_SYSTEM`, not the name).
     */
    @Test
    fun spoofedOemPackageNameIsStillOverlayAbuse() {
        val env = FakeDeviceEnvironment().apply {
            overlayPackages = listOf("com.samsung.android.malware")
            systemPackages = emptySet()
        }
        assertEquals(setOf(RiskSignal.OVERLAY_ABUSE), OverlayDetector(env).evaluate())
    }

    @Test
    fun updatedSystemAppHolderIsClean() {
        val env = FakeDeviceEnvironment().apply {
            overlayPackages = listOf("com.android.chrome")
            systemPackages = setOf("com.android.chrome")
        }
        val signals = OverlayDetector(env).evaluate()
        assertFalse(RiskSignal.OVERLAY_ABUSE in signals)
    }
}
