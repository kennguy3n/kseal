package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class JsonTest {

    @Test
    fun `objects preserve insertion order`() {
        val map = linkedMapOf<String, Any?>("z" to 1, "a" to 2, "m" to 3)
        assertEquals("""{"z":1,"a":2,"m":3}""", Json.write(map, indent = false))
    }

    @Test
    fun `strings are escaped per RFC 8259`() {
        val written = Json.write(mapOf("k" to "line\n\"q\"\tend"), indent = false)
        assertEquals("""{"k":"line\n\"q\"\tend"}""", written)
    }

    @Test
    fun `round trips nested structures`() {
        val doc = linkedMapOf<String, Any?>(
            "n" to 42L,
            "d" to 1.5,
            "b" to true,
            "nil" to null,
            "list" to listOf("a", 1L, false),
            "obj" to linkedMapOf<String, Any?>("x" to "y"),
        )
        @Suppress("UNCHECKED_CAST")
        val parsed = Json.parse(Json.write(doc)) as Map<String, Any?>
        assertEquals(42L, parsed["n"])
        assertEquals(1.5, parsed["d"])
        assertEquals(true, parsed["b"])
        assertTrue(parsed.containsKey("nil") && parsed["nil"] == null)
        assertEquals(listOf("a", 1L, false), parsed["list"])
    }

    @Test
    fun `indented output is multiline`() {
        val out = Json.write(mapOf("a" to mapOf("b" to 1)))
        assertTrue(out.contains("\n"))
        assertTrue(out.contains("  "))
    }
}
