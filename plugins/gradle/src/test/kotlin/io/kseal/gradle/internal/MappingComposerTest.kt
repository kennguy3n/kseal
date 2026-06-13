package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
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
}
