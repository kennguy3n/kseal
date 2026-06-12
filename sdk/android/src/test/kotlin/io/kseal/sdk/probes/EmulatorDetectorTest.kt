package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EmulatorDetectorTest {

    @Test
    fun physicalDeviceIsNotEmulator() {
        assertFalse(RiskSignal.EMULATOR in EmulatorDetector(FakeDeviceEnvironment()).evaluate())
    }

    @Test
    fun qemuPropertyIsEmulator() {
        val env = FakeDeviceEnvironment()
        env.systemProperties["ro.kernel.qemu"] = "1"
        assertTrue(RiskSignal.EMULATOR in EmulatorDetector(env).evaluate())
    }

    @Test
    fun goldfishHardwareIsEmulator() {
        val env = FakeDeviceEnvironment(hardware = "goldfish")
        assertTrue(RiskSignal.EMULATOR in EmulatorDetector(env).evaluate())
    }

    @Test
    fun genericFingerprintIsEmulator() {
        val env = FakeDeviceEnvironment(fingerprint = "generic/sdk_gphone_x86/generic:11/sdk:user/test-keys")
        assertTrue(RiskSignal.EMULATOR in EmulatorDetector(env).evaluate())
    }

    @Test
    fun emulatorModelIsEmulator() {
        val env = FakeDeviceEnvironment(model = "Android SDK built for x86")
        assertTrue(RiskSignal.EMULATOR in EmulatorDetector(env).evaluate())
    }

    @Test
    fun qemuPipeNodeIsEmulator() {
        val env = FakeDeviceEnvironment()
        env.existingFiles += "/dev/qemu_pipe"
        assertTrue(RiskSignal.EMULATOR in EmulatorDetector(env).evaluate())
    }

    @Test
    fun genymotionManufacturerIsEmulator() {
        val env = FakeDeviceEnvironment(manufacturer = "Genymotion")
        val signals = EmulatorDetector(env).evaluate()
        assertTrue(RiskSignal.EMULATOR in signals)
        assertTrue(RiskSignal.ENVIRONMENT in signals)
    }
}
