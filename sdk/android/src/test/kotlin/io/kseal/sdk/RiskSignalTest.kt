package io.kseal.sdk

import org.junit.Assert.assertEquals
import org.junit.Test

class RiskSignalTest {

    /** Bit indices must mirror the Rust core's RiskBitset exactly. */
    @Test
    fun bitLayoutMatchesRustCore() {
        assertEquals(0, RiskSignal.ROOT.bit)
        assertEquals(1, RiskSignal.JAILBREAK.bit)
        assertEquals(2, RiskSignal.EMULATOR.bit)
        assertEquals(3, RiskSignal.SIMULATOR.bit)
        assertEquals(4, RiskSignal.DEBUGGER.bit)
        assertEquals(5, RiskSignal.HOOKING.bit)
        assertEquals(6, RiskSignal.TAMPER.bit)
        assertEquals(7, RiskSignal.APP_INTEGRITY.bit)
        assertEquals(8, RiskSignal.NETWORK_MITM.bit)
        assertEquals(9, RiskSignal.ENVIRONMENT.bit)
        assertEquals(10, RiskSignal.PROXY.bit)
        assertEquals(11, RiskSignal.USER_CA.bit)
        assertEquals(12, RiskSignal.PINNING_FAILURE.bit)
        assertEquals(13, RiskSignal.ATTESTATION_FAIL.bit)
        assertEquals(14, RiskSignal.SECURE_HW_MISSING.bit)
        assertEquals(15, RiskSignal.REPACKAGED.bit)
        assertEquals(16, RiskSignal.SCREEN_CAPTURE.bit)
        assertEquals(17, RiskSignal.OVERLAY_ABUSE.bit)
        assertEquals(18, RiskSignal.ACCESSIBILITY_ABUSE.bit)
        assertEquals(19, RiskSignal.MALICIOUS_IME.bit)
        assertEquals(20, RiskSignal.REMOTE_ACCESS.bit)
    }

    @Test
    fun packAndUnpackRoundTrip() {
        val signals = setOf(RiskSignal.ROOT, RiskSignal.DEBUGGER, RiskSignal.PROXY)
        val bits = RiskSignal.pack(signals)
        assertEquals((1L shl 0) or (1L shl 4) or (1L shl 10), bits)
        assertEquals(signals, RiskSignal.unpack(bits))
    }

    @Test
    fun emptyPacksToZero() {
        assertEquals(0L, RiskSignal.pack(emptySet()))
        assertEquals(emptySet<RiskSignal>(), RiskSignal.unpack(0L))
    }
}
