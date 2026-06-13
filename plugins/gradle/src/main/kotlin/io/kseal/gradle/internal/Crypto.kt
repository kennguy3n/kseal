package io.kseal.gradle.internal

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptographic primitives used by the hardening pipeline.
 *
 * Everything is JDK-native (no external crypto dependency): HMAC-SHA256-based
 * HKDF for per-build key derivation and AES-256-GCM for sealing string/resource
 * payloads. The per-build polymorphism seed is the single root of entropy; every
 * transform derives an independent sub-key from it via [hkdf] with a distinct
 * `info` label, so a compromise of one derived key does not reveal the others
 * and the seed itself is never used directly as a cipher key.
 */
internal object Crypto {

    private const val HMAC_SHA256 = "HmacSHA256"
    const val SEED_BYTES = 32
    const val GCM_NONCE_BYTES = 12
    const val GCM_TAG_BITS = 128

    /** Generates a fresh cryptographically-random polymorphism seed. */
    fun randomSeed(): ByteArray = ByteArray(SEED_BYTES).also { SecureRandom().nextBytes(it) }

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    fun sha256Hex(bytes: ByteArray): String = hex(sha256(bytes))

    fun hex(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        val digits = "0123456789abcdef"
        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xff
            out[j * 2] = digits[v ushr 4]
            out[j * 2 + 1] = digits[v and 0x0f]
        }
        return String(out)
    }

    fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0) { "hex string must have even length" }
        val out = ByteArray(s.length / 2)
        for (j in out.indices) {
            out[j] = ((hexNibble(s[j * 2]) shl 4) or hexNibble(s[j * 2 + 1])).toByte()
        }
        return out
    }

    private fun hexNibble(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> error("invalid hex char '$c'")
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_SHA256)
        mac.init(SecretKeySpec(key, HMAC_SHA256))
        return mac.doFinal(data)
    }

    /**
     * RFC 5869 HKDF (extract-then-expand) over HMAC-SHA256. `info` namespaces each
     * derived key so distinct transforms never collide.
     */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..(255 * 32)) { "invalid HKDF output length: $length" }
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            val mac = Mac.getInstance(HMAC_SHA256)
            mac.init(SecretKeySpec(prk, HMAC_SHA256))
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val n = minOf(t.size, length - pos)
            System.arraycopy(t, 0, out, pos, n)
            pos += n
            counter++
        }
        return out
    }

    /** Derives a labelled 256-bit sub-key from the seed. */
    fun deriveKey(seed: ByteArray, label: String): ByteArray =
        hkdf(seed, salt = "io.kseal.harden".toByteArray(), info = label.toByteArray(), length = 32)

    /**
     * AES-256-GCM seal. The 12-byte nonce is derived deterministically from the
     * key and plaintext-identity ([nonceContext]) rather than randomly, so the
     * same input under the same seed produces byte-identical output — essential
     * for build caching and reproducible builds — while distinct contexts never
     * reuse a (key, nonce) pair. The nonce is prepended to the ciphertext.
     */
    fun seal(key: ByteArray, plaintext: ByteArray, nonceContext: String): ByteArray {
        val nonce = hkdf(key, salt = nonceContext.toByteArray(), info = "gcm-nonce".toByteArray(), length = GCM_NONCE_BYTES)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        val ct = cipher.doFinal(plaintext)
        return nonce + ct
    }

    /** Inverse of [seal]; verifies the GCM tag. */
    fun open(key: ByteArray, sealed: ByteArray): ByteArray {
        require(sealed.size > GCM_NONCE_BYTES) { "sealed payload too short" }
        val nonce = sealed.copyOfRange(0, GCM_NONCE_BYTES)
        val ct = sealed.copyOfRange(GCM_NONCE_BYTES, sealed.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        return cipher.doFinal(ct)
    }
}
