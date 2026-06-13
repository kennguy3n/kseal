package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class CryptoTest {

    @Test
    fun `hex round trips`() {
        val bytes = ByteArray(256) { it.toByte() }
        assertArrayEquals(bytes, Crypto.unhex(Crypto.hex(bytes)))
    }

    @Test
    fun `hkdf matches RFC 5869 test case 1`() {
        // RFC 5869, Appendix A.1 (SHA-256).
        val ikm = Crypto.unhex("0b".repeat(22))
        val salt = Crypto.unhex("000102030405060708090a0b0c")
        val info = Crypto.unhex("f0f1f2f3f4f5f6f7f8f9")
        val okm = Crypto.hkdf(ikm, salt, info, 42)
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a" +
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865",
            Crypto.hex(okm),
        )
    }

    @Test
    fun `derived keys differ by label and are 256 bits`() {
        val seed = Crypto.unhex("11".repeat(32))
        val a = Crypto.deriveKey(seed, "string-resource-seal")
        val b = Crypto.deriveKey(seed, "string-resource-token")
        assertEquals(32, a.size)
        assertNotEquals(Crypto.hex(a), Crypto.hex(b))
    }

    @Test
    fun `seal is deterministic per key+context and opens`() {
        val key = Crypto.deriveKey(Crypto.unhex("22".repeat(32)), "seal")
        val pt = "the quick brown fox".toByteArray()
        val first = Crypto.seal(key, pt, nonceContext = "ctx")
        val second = Crypto.seal(key, pt, nonceContext = "ctx")
        assertArrayEquals(first, second, "deterministic nonce must give identical ciphertext")
        assertArrayEquals(pt, Crypto.open(key, first))
    }

    @Test
    fun `tampered ciphertext fails GCM tag`() {
        val key = Crypto.deriveKey(Crypto.unhex("33".repeat(32)), "seal")
        val sealed = Crypto.seal(key, "secret".toByteArray(), "ctx")
        sealed[sealed.size - 1] = (sealed[sealed.size - 1] + 1).toByte()
        assertThrows(Exception::class.java) { Crypto.open(key, sealed) }
    }
}
