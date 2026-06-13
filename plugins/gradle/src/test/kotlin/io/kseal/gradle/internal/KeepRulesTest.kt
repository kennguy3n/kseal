package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class KeepRulesTest {

    @Test
    fun `parses keep directives and matches class names`() {
        val rules = KeepRules.parse(
            """
            # comment
            -keep class com.example.Api { *; }
            -keepclassmembers class com.example.model.** implements java.io.Serializable
            -dontwarn something.else
            -keepnames class com.example.reflect.Handler
            """.trimIndent(),
        )
        assertTrue(rules.keepsClass("com.example.Api"))
        assertTrue(rules.keepsClass("com.example.model.User"))
        assertTrue(rules.keepsClass("com.example.reflect.Handler"))
        assertFalse(rules.keepsClass("com.example.Internal"))
    }

    @Test
    fun `single star does not cross package separator`() {
        val rules = KeepRules.parse("-keep class com.example.* { *; }")
        assertTrue(rules.keepsClass("com.example.Foo"))
        assertFalse(rules.keepsClass("com.example.sub.Foo"))
    }

    @Test
    fun `double star crosses package separators`() {
        val rules = KeepRules.parse("-keep class com.example.** { *; }")
        assertTrue(rules.keepsClass("com.example.sub.deep.Foo"))
    }

    @Test
    fun `comma-separated directive modifiers are honoured`() {
        val rules = KeepRules.parse(
            """
            -keep,allowobfuscation class com.example.Reflected
            -keepclassmembers,includedescriptorclasses class com.example.Native { native <methods>; }
            """.trimIndent(),
        )
        assertTrue(rules.keepsClass("com.example.Reflected"))
        assertTrue(rules.keepsClass("com.example.Native"))
    }

    @Test
    fun `extra name globs are honoured`() {
        val rules = KeepRules.parse("", extraNameGlobs = listOf("app_name", "url_*"))
        assertTrue(rules.keepsName("app_name"))
        assertTrue(rules.keepsName("url_base"))
        assertFalse(rules.keepsName("secret_token"))
    }
}
