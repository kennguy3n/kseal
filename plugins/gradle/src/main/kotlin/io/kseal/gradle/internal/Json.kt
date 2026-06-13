package io.kseal.gradle.internal

/**
 * A small, dependency-free JSON reader/writer.
 *
 * The plugin emits a strictly-shaped build-proof manifest and a Connect-protocol
 * `CreateBuildRequest`, and reads back a flat `CreateBuildResponse`. Pulling in a
 * full JSON library would bloat the plugin classpath (and risk clashing with a
 * consumer's own version), so we implement exactly the subset we need, correctly:
 * RFC 8259 string escaping on write and a complete recursive-descent parser on
 * read. The writer emits objects with insertion-ordered keys for stable,
 * diff-friendly, reproducible output.
 */
internal object Json {

    /** Serializes a value tree ([Map], [List], [String], [Number], [Boolean], null). */
    fun write(value: Any?, indent: Boolean = true): String {
        val sb = StringBuilder()
        writeValue(sb, value, if (indent) 0 else -1)
        return sb.toString()
    }

    /** Parses a JSON document into a value tree. */
    fun parse(text: String): Any? = Parser(text).parseDocument()

    private fun writeValue(sb: StringBuilder, value: Any?, depth: Int) {
        when (value) {
            null -> sb.append("null")
            is String -> writeString(sb, value)
            is Boolean -> sb.append(value.toString())
            is Int, is Long, is Short, is Byte -> sb.append(value.toString())
            is Double, is Float -> {
                val d = (value as Number).toDouble()
                require(d.isFinite()) { "non-finite numbers are not valid JSON" }
                sb.append(value.toString())
            }
            is Map<*, *> -> writeObject(sb, value, depth)
            is List<*> -> writeArray(sb, value, depth)
            else -> error("unsupported JSON value type: ${value::class.java.name}")
        }
    }

    private fun writeObject(sb: StringBuilder, map: Map<*, *>, depth: Int) {
        if (map.isEmpty()) {
            sb.append("{}")
            return
        }
        sb.append('{')
        val nextDepth = if (depth < 0) -1 else depth + 1
        var first = true
        for ((k, v) in map) {
            if (!first) sb.append(',')
            first = false
            newlineIndent(sb, nextDepth)
            writeString(sb, k.toString())
            sb.append(if (depth < 0) ":" else ": ")
            writeValue(sb, v, nextDepth)
        }
        newlineIndent(sb, depth)
        sb.append('}')
    }

    private fun writeArray(sb: StringBuilder, list: List<*>, depth: Int) {
        if (list.isEmpty()) {
            sb.append("[]")
            return
        }
        sb.append('[')
        val nextDepth = if (depth < 0) -1 else depth + 1
        var first = true
        for (v in list) {
            if (!first) sb.append(',')
            first = false
            newlineIndent(sb, nextDepth)
            writeValue(sb, v, nextDepth)
        }
        newlineIndent(sb, depth)
        sb.append(']')
    }

    private fun newlineIndent(sb: StringBuilder, depth: Int) {
        if (depth < 0) return
        sb.append('\n')
        repeat(depth) { sb.append("  ") }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else ->
                    if (c < ' ') sb.append("\\u%04x".format(c.code))
                    else sb.append(c)
            }
        }
        sb.append('"')
    }

    private class Parser(private val s: String) {
        private var i = 0

        fun parseDocument(): Any? {
            skipWs()
            val v = parseValue()
            skipWs()
            require(i >= s.length) { "trailing content at offset $i" }
            return v
        }

        private fun parseValue(): Any? {
            skipWs()
            check(i < s.length) { "unexpected end of input" }
            return when (s[i]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't', 'f' -> parseBoolean()
                'n' -> parseNull()
                else -> parseNumber()
            }
        }

        private fun parseObject(): Map<String, Any?> {
            expect('{')
            val out = LinkedHashMap<String, Any?>()
            skipWs()
            if (peek() == '}') { i++; return out }
            while (true) {
                skipWs()
                val key = parseString()
                skipWs()
                expect(':')
                out[key] = parseValue()
                skipWs()
                when (val c = next()) {
                    ',' -> continue
                    '}' -> break
                    else -> error("expected ',' or '}' but found '$c'")
                }
            }
            return out
        }

        private fun parseArray(): List<Any?> {
            expect('[')
            val out = ArrayList<Any?>()
            skipWs()
            if (peek() == ']') { i++; return out }
            while (true) {
                out.add(parseValue())
                skipWs()
                when (val c = next()) {
                    ',' -> continue
                    ']' -> break
                    else -> error("expected ',' or ']' but found '$c'")
                }
            }
            return out
        }

        private fun parseString(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                check(i < s.length) { "unterminated string" }
                when (val c = s[i++]) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        check(i < s.length) { "unterminated escape" }
                        when (val e = s[i++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'u' -> {
                                check(i + 4 <= s.length) { "truncated unicode escape" }
                                val hex = s.substring(i, i + 4)
                                i += 4
                                sb.append(hex.toInt(16).toChar())
                            }
                            else -> error("invalid escape '\\$e'")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun parseBoolean(): Boolean =
            when {
                s.startsWith("true", i) -> { i += 4; true }
                s.startsWith("false", i) -> { i += 5; false }
                else -> error("invalid literal at offset $i")
            }

        private fun parseNull(): Any? {
            require(s.startsWith("null", i)) { "invalid literal at offset $i" }
            i += 4
            return null
        }

        private fun parseNumber(): Any {
            val start = i
            if (peek() == '-') i++
            while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
            val token = s.substring(start, i)
            require(token.isNotEmpty()) { "invalid number at offset $start" }
            return if (token.any { it == '.' || it == 'e' || it == 'E' }) {
                token.toDouble()
            } else {
                token.toLong()
            }
        }

        private fun skipWs() {
            while (i < s.length && s[i].isWhitespace()) i++
        }

        private fun peek(): Char {
            check(i < s.length) { "unexpected end of input" }
            return s[i]
        }

        private fun next(): Char {
            check(i < s.length) { "unexpected end of input" }
            return s[i++]
        }

        private fun expect(c: Char) {
            val actual = next()
            require(actual == c) { "expected '$c' but found '$actual' at offset ${i - 1}" }
        }
    }
}
