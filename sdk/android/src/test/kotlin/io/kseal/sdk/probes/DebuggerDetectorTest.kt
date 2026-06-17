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

    @Test
    fun nativeDebuggerPresentIsDebugger() {
        val env = FakeDeviceEnvironment().apply { nativeDebugger = 1 }
        assertEquals(setOf(RiskSignal.DEBUGGER), DebuggerDetector(env).evaluate())
    }

    @Test
    fun nativeDebuggerUnavailableIsClean() {
        // The "unavailable" sentinel (-1) must never raise a signal.
        val env = FakeDeviceEnvironment().apply { nativeDebugger = -1 }
        assertTrue(DebuggerDetector(env).evaluate().isEmpty())
    }
}
