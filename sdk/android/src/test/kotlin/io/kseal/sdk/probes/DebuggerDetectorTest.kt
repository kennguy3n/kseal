package io.kseal.sdk.probes

import io.kseal.sdk.RiskSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DebuggerDetectorTest {

    @Test
    fun noDebuggerIsClean() {
        assertTrue(DebuggerDetector(FakeDeviceEnvironment()).evaluate().isEmpty())
    }

    @Test
    fun jdwpConnectedIsDebugger() {
        val env = FakeDeviceEnvironment().apply { debuggerConnected = true }
        assertEquals(setOf(RiskSignal.DEBUGGER), DebuggerDetector(env).evaluate())
    }

    @Test
    fun nonZeroTracerPidIsDebugger() {
        val env = FakeDeviceEnvironment().apply { tracerPid = 2451 }
        assertEquals(setOf(RiskSignal.DEBUGGER), DebuggerDetector(env).evaluate())
    }

    @Test
    fun zeroTracerPidIsClean() {
        val env = FakeDeviceEnvironment().apply { tracerPid = 0 }
        assertTrue(DebuggerDetector(env).evaluate().isEmpty())
    }
}
