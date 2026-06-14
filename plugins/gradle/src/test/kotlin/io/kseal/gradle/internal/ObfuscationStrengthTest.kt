package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ObfuscationStrengthTest {

    @Test
    fun `parses the canonical levels case-insensitively and trims whitespace`() {
        assertEquals(ObfuscationStrength.OFF, ObfuscationStrength.parseStrict("off"))
        assertEquals(ObfuscationStrength.LOW, ObfuscationStrength.parseStrict("LOW"))
        assertEquals(ObfuscationStrength.MEDIUM, ObfuscationStrength.parseStrict("  Medium "))
        assertEquals(ObfuscationStrength.HIGH, ObfuscationStrength.parseStrict("high"))
    }

    @Test
    fun `unknown strength fails loudly instead of silently downgrading`() {
        val ex = assertThrows(IllegalArgumentException::class.java) {
            ObfuscationStrength.parseStrict("hihg")
        }
        assertTrue(ex.message!!.contains("hihg"), "echoes the offending value")
        assertTrue(ex.message!!.contains("off, low, medium, high"), "lists the valid values")
    }

    @Test
    fun `null and blank are rejected rather than defaulted`() {
        assertThrows(IllegalArgumentException::class.java) { ObfuscationStrength.parseStrict(null) }
        assertThrows(IllegalArgumentException::class.java) { ObfuscationStrength.parseStrict("   ") }
    }

    @Test
    fun `off performs no transforms while higher levels escalate opaque-predicate density`() {
        val off = ObfuscationStrength.OFF.toOptions(emptySet())
        assertEquals(false, off.encryptStrings)
        assertEquals(false, off.opaquePredicates)

        val low = ObfuscationStrength.LOW.toOptions(emptySet())
        assertEquals(true, low.encryptStrings)
        assertEquals(false, low.opaquePredicates)

        val medium = ObfuscationStrength.MEDIUM.toOptions(emptySet())
        val high = ObfuscationStrength.HIGH.toOptions(emptySet())
        assertTrue(medium.opaquePredicates && high.opaquePredicates)
        assertTrue(high.opaqueDensity > medium.opaqueDensity, "high covers more methods than medium")
    }
}
