package io.kseal.gradle.internal

/**
 * A glob/ProGuard-style name matcher.
 *
 * Supports the subset of wildcards the hardening passes need:
 *  - `**` matches any sequence including the package separator `.` / path `/`.
 *  - `*`  matches any sequence **not** crossing a `.` or `/` separator.
 *  - `?`  matches a single non-separator character.
 *
 * This mirrors ProGuard/R8 class-spec semantics closely enough to decide, safely
 * and conservatively, whether a given symbol is covered by a keep rule.
 */
internal class NameMatcher private constructor(private val regex: Regex) {
    fun matches(name: String): Boolean = regex.matches(name)

    companion object {
        fun of(pattern: String): NameMatcher = NameMatcher(toRegex(pattern.trim()))

        private fun toRegex(pattern: String): Regex {
            val sb = StringBuilder("^")
            var i = 0
            while (i < pattern.length) {
                val c = pattern[i]
                when (c) {
                    '*' ->
                        if (i + 1 < pattern.length && pattern[i + 1] == '*') {
                            sb.append(".*"); i++
                        } else {
                            sb.append("[^./]*")
                        }
                    '?' -> sb.append("[^./]")
                    '.', '\\', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|' ->
                        sb.append('\\').append(c)
                    '/' -> sb.append("[./]") // treat package + path separators alike
                    else -> sb.append(c)
                }
                i++
            }
            sb.append('$')
            return Regex(sb.toString())
        }
    }
}

/**
 * The set of symbols the hardening passes must leave untouched so the app keeps
 * working: anything matched by a ProGuard/R8 `-keep*` rule (reflection,
 * serialization, JNI entry points, public API), plus any caller-supplied keep
 * globs for string-resource keys.
 *
 * Parsing is deliberately conservative — when a rule's class spec cannot be
 * understood it is treated as a broad keep (fail safe: keep more, obfuscate less)
 * rather than risking obfuscation of a reflectively-referenced symbol.
 */
internal class KeepRules(
    private val classMatchers: List<NameMatcher>,
    private val nameMatchers: List<NameMatcher>,
) {
    fun keepsClass(name: String): Boolean = classMatchers.any { it.matches(name) }

    /** True when [name] (a resource/string key) must not be obfuscated. */
    fun keepsName(name: String): Boolean =
        nameMatchers.any { it.matches(name) } || classMatchers.any { it.matches(name) }

    companion object {
        private val KEEP_DIRECTIVES = setOf(
            "-keep", "-keepnames",
            "-keepclassmembers", "-keepclassmembernames",
            "-keepclasseswithmembers", "-keepclasseswithmembernames",
        )

        fun parse(ruleText: String, extraNameGlobs: List<String> = emptyList()): KeepRules {
            val classMatchers = ArrayList<NameMatcher>()
            // Strip line comments, then collapse to a directive stream.
            val cleaned = ruleText.lineSequence()
                .map { line -> line.substringBefore('#').trim() }
                .filter { it.isNotEmpty() }
                .joinToString("\n")

            var idx = 0
            while (idx < cleaned.length) {
                val dashAt = cleaned.indexOf('-', idx)
                if (dashAt < 0) break
                val end = nextDirectiveStart(cleaned, dashAt + 1)
                val directive = cleaned.substring(dashAt, end)
                idx = end
                val keyword = directive.takeWhile { !it.isWhitespace() }
                if (keyword !in KEEP_DIRECTIVES) continue
                classNameOf(directive)?.let { classMatchers.add(NameMatcher.of(it)) }
            }

            val nameMatchers = extraNameGlobs.filter { it.isNotBlank() }.map { NameMatcher.of(it) }
            return KeepRules(classMatchers, nameMatchers)
        }

        private fun nextDirectiveStart(text: String, from: Int): Int {
            var i = from
            while (i < text.length) {
                if (text[i] == '-' && (i == 0 || text[i - 1] == '\n')) return i
                i++
            }
            return text.length
        }

        /**
         * Extracts the class-name token from a keep directive, skipping option
         * flags (`-keep,includedescriptorclasses`), the spec keyword
         * (`class`/`interface`/`enum`/`@interface`), annotations (`@Foo`), and
         * access modifiers, and dropping any `{ ... }` member block.
         */
        private fun classNameOf(directive: String): String? {
            val withoutBody = directive.substringBefore('{').trim()
            val tokens = withoutBody.split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (tokens.isEmpty()) return null
            val modifiers = setOf(
                "class", "interface", "enum", "public", "private", "protected",
                "abstract", "final", "static",
            )
            var i = 1 // skip the directive keyword itself
            while (i < tokens.size) {
                val t = tokens[i]
                when {
                    t.startsWith("@") -> i++ // annotation type (or @interface keyword)
                    t == "!" || t.startsWith("!") -> i++
                    t in modifiers -> i++
                    else -> return normalizeClassName(t)
                }
            }
            return null
        }

        private fun normalizeClassName(token: String): String? {
            // Drop trailing `implements`/`extends` clauses if glued on, and any stray
            // commas; keep the bare type pattern.
            val name = token.substringBefore(',').trim()
            return name.ifBlank { null }
        }
    }
}
