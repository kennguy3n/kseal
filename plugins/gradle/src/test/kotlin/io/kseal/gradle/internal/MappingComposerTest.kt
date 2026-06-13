package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MappingComposerTest {

    private val r8 =
        """
        com.example.App -> a.a.a:
            int field -> a
            void method() -> b
        """.trimIndent()

    @Test
    fun `r8 mapping is preserved verbatim at the top`() {
        val composed = MappingComposer.compose(r8, "deadbeef", mapOf("kseal_01" to "api_secret"))
        assertEquals(r8, MappingComposer.r8PortionOf(composed))
        assertTrue(composed.contains("# seed-digest: deadbeef"))
        assertTrue(composed.contains("# token kseal_01 -> api_secret"))
    }

    @Test
    fun `handles absent r8 mapping`() {
        val composed = MappingComposer.compose(null, "abc123", emptyMap())
        assertEquals("", MappingComposer.r8PortionOf(composed))
        assertTrue(composed.startsWith(MappingComposer.ADDENDUM_HEADER))
    }

    @Test
    fun `omitting the obfuscation block keeps output byte-identical`() {
        val withoutArg = MappingComposer.compose(r8, "deadbeef", mapOf("kseal_01" to "api_secret"))
        val withNull = MappingComposer.compose(r8, "deadbeef", mapOf("kseal_01" to "api_secret"), obfuscation = null)
        assertEquals(withoutArg, withNull)
        assertFalse(withNull.contains("bytecode-obfuscation"))
    }

    @Test
    fun `obfuscation block records structure without leaking plaintext and preserves r8 mapping`() {
        val composed = MappingComposer.compose(
            r8,
            "deadbeef",
            mapOf("kseal_01" to "api_secret"),
            obfuscation = MappingComposer.Obfuscation(
                strength = "high",
                decoderClass = "io/kseal/generated/KsealStrings",
                uniqueStringsEncrypted = 12,
                stringLoadsRewritten = 30,
                opaquePredicatesInserted = 7,
            ),
        )
        // R8 mapping is still preserved verbatim at the top — symbolication survives.
        assertEquals(r8, MappingComposer.r8PortionOf(composed))
        assertTrue(composed.contains("# bytecode-obfuscation: strength=high strings=12 rewrites=30 opaque-predicates=7"))
        assertTrue(composed.contains("# bytecode-string-decoder: io/kseal/generated/KsealStrings"))
        // The whole addendum is comments, so retrace ignores it.
        val addendum = composed.substringAfter(MappingComposer.ADDENDUM_HEADER)
        assertTrue(addendum.lines().all { it.isEmpty() || it.startsWith("#") })
    }
}
