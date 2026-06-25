package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NativeStringObfuscationInspectorTest {

    private fun bytesOf(vararg parts: String): ByteArray =
        parts.joinToString("\u0000").toByteArray(Charsets.US_ASCII)

    @Test
    fun `kseal core without sentinels is reported obfuscated`() {
        // Exported C ABI names stay plaintext (they must), but no sensitive
        // literal is present -> the hardened build was shipped.
        val bytes = bytesOf("kseal_evaluate_risk", "kseal_load_config", "some.unrelated.symbol")
        val r = NativeStringObfuscationInspector.inspectBytes(bytes)

        assertEquals(NativeStringObfuscationInspector.Status.OBFUSCATED, r.status)
        assertTrue(r.isKsealCore)
        assertTrue(r.markersFound.isEmpty())
    }

    @Test
    fun `kseal core with a sentinel literal is reported plaintext`() {
        val bytes = bytesOf("kseal_load_config", "config signature verification failed", "network_mitm")
        val r = NativeStringObfuscationInspector.inspectBytes(bytes)

        assertEquals(NativeStringObfuscationInspector.Status.PLAINTEXT, r.status)
        assertTrue(r.isKsealCore)
        assertTrue(r.markersFound.contains("config signature verification failed"))
        assertTrue(r.markersFound.contains("network_mitm"))
        assertFalse(r.notes.isEmpty())
    }

    @Test
    fun `non-kseal library is not asserted`() {
        // A third-party .so we did not build must not be falsely reported clean.
        val bytes = bytesOf("JNI_OnLoad", "config signature verification failed")
        val r = NativeStringObfuscationInspector.inspectBytes(bytes)

        assertEquals(NativeStringObfuscationInspector.Status.NOT_APPLICABLE, r.status)
        assertFalse(r.isKsealCore)
        assertTrue(r.markersFound.isEmpty())
    }

    @Test
    fun `ambiguous short tokens alone do not flag plaintext`() {
        // "root"/"debugger"/"emulator" are emitted by proto reflection regardless
        // of obfuscation, so they are deliberately not sentinels.
        val bytes = bytesOf("kseal_evaluate_risk", "root", "debugger", "emulator")
        val r = NativeStringObfuscationInspector.inspectBytes(bytes)

        assertEquals(NativeStringObfuscationInspector.Status.OBFUSCATED, r.status)
    }

    @Test
    fun `wire names are stable for the manifest contract`() {
        assertEquals("obfuscated", NativeStringObfuscationInspector.Status.OBFUSCATED.wire)
        assertEquals("plaintext", NativeStringObfuscationInspector.Status.PLAINTEXT.wire)
        assertEquals("not-applicable", NativeStringObfuscationInspector.Status.NOT_APPLICABLE.wire)
        assertEquals("indeterminate", NativeStringObfuscationInspector.Status.INDETERMINATE.wire)
    }
}
