package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HookDetectorTest {

    @Test
    fun cleanProcessIsClean() {
        val env = FakeDeviceEnvironment().apply {
            maps = listOf(
                "7f0000000000-7f0000001000 r-xp 00000000 fd:00 1 /system/lib64/libc.so",
                "7f0000002000-7f0000003000 r-xp 00000000 fd:00 2 /system/lib64/libart.so",
            )
        }
        assertTrue(HookDetector(env).evaluate().isEmpty())
    }

    @Test
    fun fridaInMapsIsHooking() {
        val env = FakeDeviceEnvironment().apply {
            maps = listOf("7f00-7f01 r-xp 0 fd:00 9 /data/local/tmp/re.frida.server/frida-agent-64.so")
        }
        assertEquals(setOf(RiskSignal.HOOKING), HookDetector(env).evaluate())
    }

    @Test
    fun xposedInMapsIsHooking() {
        val env = FakeDeviceEnvironment().apply {
            maps = listOf("7f00-7f01 r-xp 0 fd:00 9 /system/framework/XposedBridge.jar")
        }
        assertTrue(RiskSignal.HOOKING in HookDetector(env).evaluate())
    }

    @Test
    fun fridaServerArtifactIsHooking() {
        val env = FakeDeviceEnvironment()
        env.existingFiles += "/data/local/tmp/frida-server"
        assertTrue(RiskSignal.HOOKING in HookDetector(env).evaluate())
    }

    @Test
    fun fridaPortOpenIsHooking() {
        val env = FakeDeviceEnvironment().apply { openPorts += 27042 }
        assertTrue(RiskSignal.HOOKING in HookDetector(env).evaluate())
    }

    @Test
    fun xposedPackageIsHooking() {
        val env = FakeDeviceEnvironment()
        env.packages = env.packages + "de.robv.android.xposed.installer"
        assertTrue(RiskSignal.HOOKING in HookDetector(env).evaluate())
    }

    @Test
    fun nativeHookPresentIsHooking() {
        val env = FakeDeviceEnvironment().apply { nativeHook = 1 }
        assertEquals(setOf(RiskSignal.HOOKING), HookDetector(env).evaluate())
    }

    @Test
    fun nativeHookUnavailableIsClean() {
        // The "unavailable" sentinel (-1) must never raise a signal.
        val env = FakeDeviceEnvironment().apply { nativeHook = -1 }
        assertTrue(HookDetector(env).evaluate().isEmpty())
    }
}
