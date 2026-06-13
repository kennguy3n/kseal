package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ResourceHardenerTest {

    private val seed = Crypto.unhex("44".repeat(32))

    private fun strings(vararg pairs: Pair<String, String>): List<ResourceHardener.ResFile> {
        val body = pairs.joinToString("\n") { (k, v) -> """    <string name="$k">$v</string>""" }
        return listOf(
            ResourceHardener.ResFile(
                "values/strings.xml",
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n$body\n</resources>",
            ),
        )
    }

    @Test
    fun `seals non-kept values and recovers them`() {
        val keep = KeepRules.parse("", extraNameGlobs = listOf("app_name"))
        val result = ResourceHardener.harden(
            strings("app_name" to "Demo", "api_secret" to "s3cr3t-value"),
            keep,
            seed,
        )
        assertEquals(1, result.sealedCount)
        assertEquals(1, result.keptCount)

        val xml = result.transformedFiles.values.single()
        assertTrue(xml.contains(">Demo<"), "kept value stays in clear")
        assertFalse(xml.contains("s3cr3t-value"), "sealed value must not appear in clear")

        val key = Crypto.deriveKey(seed, "string-resource-seal")
        @Suppress("UNCHECKED_CAST")
        val opened = Json.parse(String(Crypto.open(key, result.sealedBlob))) as Map<String, Any?>
        assertEquals("s3cr3t-value", opened.values.single())
    }

    @Test
    fun `fully-qualified class-name values are kept in clear for reflection`() {
        val result = ResourceHardener.harden(
            strings("handler" to "com.example.MyHandler"),
            KeepRules.parse(""),
            seed,
        )
        assertEquals(0, result.sealedCount)
        assertEquals(1, result.keptCount)
        assertTrue(result.transformedFiles.values.single().contains("com.example.MyHandler"))
    }

    @Test
    fun `output is deterministic per seed and polymorphic across seeds`() {
        val keep = KeepRules.parse("")
        val a = ResourceHardener.harden(strings("k" to "v"), keep, seed)
        val b = ResourceHardener.harden(strings("k" to "v"), keep, seed)
        assertArrayEquals(a.sealedBlob, b.sealedBlob)
        assertEquals(a.tokenToKey, b.tokenToKey)

        val other = ResourceHardener.harden(strings("k" to "v"), keep, Crypto.unhex("55".repeat(32)))
        assertFalse(a.tokenToKey.keys == other.tokenToKey.keys, "tokens must be re-permuted per seed")
    }
}
