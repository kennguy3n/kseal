package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteAccessDetectorTest {

    @Test
    fun cleanDeviceIsClean() {
        assertTrue(RemoteAccessDetector(FakeDeviceEnvironment()).evaluate().isEmpty())
    }

    @Test
    fun adbEnabledIsRemoteAccess() {
        val env = FakeDeviceEnvironment().apply { adbEnabled = true }
        assertEquals(setOf(RiskSignal.REMOTE_ACCESS), RemoteAccessDetector(env).evaluate())
    }

    @Test
    fun anyDeskInstalledIsRemoteAccess() {
        val env = FakeDeviceEnvironment().apply {
            packages = listOf("com.android.vending", "com.example.host", "com.anydesk.anydeskandroid")
        }
        assertTrue(RiskSignal.REMOTE_ACCESS in RemoteAccessDetector(env).evaluate())
    }

    @Test
    fun teamViewerQuickSupportVariantIsRemoteAccess() {
        // Substring match must catch vendor host/support package variants.
        val env = FakeDeviceEnvironment().apply {
            packages = listOf("com.example.host", "com.teamviewer.quicksupport.market")
        }
        assertTrue(RiskSignal.REMOTE_ACCESS in RemoteAccessDetector(env).evaluate())
    }

    @Test
    fun rustDeskInstalledIsRemoteAccess() {
        val env = FakeDeviceEnvironment().apply {
            packages = listOf("com.example.host", "com.carriez.flutter_hbb")
        }
        assertTrue(RiskSignal.REMOTE_ACCESS in RemoteAccessDetector(env).evaluate())
    }

    @Test
    fun ordinaryAppsAreClean() {
        val env = FakeDeviceEnvironment().apply {
            packages = listOf("com.android.vending", "com.example.host", "com.whatsapp", "com.spotify.music")
        }
        assertFalse(RiskSignal.REMOTE_ACCESS in RemoteAccessDetector(env).evaluate())
    }
}
