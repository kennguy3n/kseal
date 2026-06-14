package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SeedDeriverTest {

    private fun inputs(
        explicit: String? = null,
        randomize: Boolean = false,
        master: String? = null,
        salt: String = "io.kseal:app",
        digest: String = Crypto.sha256Hex("inputs".toByteArray()),
    ) = SeedDeriver.Inputs(explicit, randomize, master, salt, digest)

    @Test
    fun `explicit seed is used verbatim`() {
        val hex = "ab".repeat(32)
        assertArrayEquals(Crypto.unhex(hex), SeedDeriver.derive(inputs(explicit = hex)))
    }

    @Test
    fun `explicit seed tolerates surrounding whitespace and mixed case`() {
        val hex = "Ab".repeat(32)
        assertArrayEquals(Crypto.unhex(hex.lowercase()), SeedDeriver.derive(inputs(explicit = "  $hex\n")))
    }

    @Test
    fun `explicit seed of the wrong length fails with an actionable message`() {
        val ex = assertThrows(IllegalArgumentException::class.java) {
            SeedDeriver.derive(inputs(explicit = "abcd"))
        }
        assertTrue(ex.message!!.contains("explicitSeedHex"), "names the offending DSL property")
        assertTrue(ex.message!!.contains("64 hex characters"), "states the expected length")
        assertTrue(ex.message!!.contains("openssl rand -hex 32"), "tells the user how to generate one")
    }

    @Test
    fun `explicit seed of correct length but non-hex reports the encoding fault, not a length one`() {
        // 64 chars (the expected length) but invalid hex: the message must point
        // at the encoding, not claim a length problem the user doesn't have.
        val ex = assertThrows(IllegalArgumentException::class.java) {
            SeedDeriver.derive(inputs(explicit = "zz".repeat(32)))
        }
        assertTrue(ex.message!!.contains("explicitSeedHex"), "names the offending DSL property")
        assertTrue(ex.message!!.contains("non-hex characters"), "calls out the encoding fault")
        assertFalse(ex.message!!.contains("got 64 character(s)"), "must not imply the length is wrong")
        assertTrue(ex.message!!.contains("openssl rand -hex 32"), "tells the user how to generate one")
    }

    @Test
    fun `content derivation is deterministic and depends on inputs`() {
        val a = SeedDeriver.derive(inputs())
        val b = SeedDeriver.derive(inputs())
        assertArrayEquals(a, b)
        val c = SeedDeriver.derive(inputs(digest = Crypto.sha256Hex("other".toByteArray())))
        assertFalse(Crypto.hex(a) == Crypto.hex(c))
        assertEquals(Crypto.SEED_BYTES, a.size)
    }

    @Test
    fun `master key changes the derived seed`() {
        val withoutMaster = SeedDeriver.derive(inputs())
        val withMaster = SeedDeriver.derive(inputs(master = "cd".repeat(32)))
        assertFalse(Crypto.hex(withoutMaster) == Crypto.hex(withMaster))
    }

    @Test
    fun `random seeds differ across invocations`() {
        val a = SeedDeriver.derive(inputs(randomize = true))
        val b = SeedDeriver.derive(inputs(randomize = true))
        assertFalse(Crypto.hex(a) == Crypto.hex(b))
    }
}
