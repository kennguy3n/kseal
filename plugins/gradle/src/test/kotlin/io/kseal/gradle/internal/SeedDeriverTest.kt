package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
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
