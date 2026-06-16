package io.kseal.gradle.internal

/**
 * Composes the R8 `mapping.txt` with kseal's own obfuscation addendum so crash
 * symbolication keeps working end-to-end.
 *
 * R8's mapping is reproduced **verbatim and first** — Play Console / retrace and
 * any crash-reporting pipeline read those lines unchanged. kseal then appends a
 * machine-readable addendum (as `#` comment lines, which retrace ignores)
 * recording the per-build seed digest and every string-resource token → original
 * key mapping, so kseal's de-obfuscation tooling can reverse the build-time
 * transforms without disturbing standard symbolication.
 *
 * The bytecode control-flow obfuscation pass is **name-preserving** (it renames
 * nothing), so R8's mapping keeps resolving unchanged; the optional
 * [Obfuscation] block only records *structural* facts (which transforms ran, the
 * generated decoder class, counts) so the addendum fully describes what kseal did
 * to the build. Plaintext string values are never recorded — that would defeat
 * the encryption and leak tenant data.
 */
internal object MappingComposer {

    const val ADDENDUM_HEADER = "# kseal-build-proof mapping addendum v1"

    /** Privacy-safe structural summary of the bytecode obfuscation pass. */
    data class Obfuscation(
        val strength: String,
        val decoderClass: String?,
        val uniqueStringsEncrypted: Int,
        val stringLoadsRewritten: Int,
        val opaquePredicatesInserted: Int,
        val methodsFlattened: Int = 0,
        val flattenedBlocks: Int = 0,
        val mbaSubstitutions: Int = 0,
    )

    fun compose(
        r8Mapping: String?,
        seedDigestHex: String,
        resourceTokens: Map<String, String>,
        obfuscation: Obfuscation? = null,
    ): String {
        val sb = StringBuilder()
        val base = r8Mapping?.trimEnd().orEmpty()
        if (base.isNotEmpty()) {
            sb.append(base).append('\n')
        }
        sb.append(ADDENDUM_HEADER).append('\n')
        sb.append("# seed-digest: ").append(seedDigestHex).append('\n')
        sb.append("# string-resource-seal: ").append(resourceTokens.size).append(" entries\n")
        // Stable ordering for reproducible output and clean diffs.
        for ((token, original) in resourceTokens.toSortedMap()) {
            sb.append("# token ").append(token).append(" -> ").append(original).append('\n')
        }
        if (obfuscation != null) {
            sb.append("# bytecode-obfuscation: strength=").append(obfuscation.strength)
                .append(" strings=").append(obfuscation.uniqueStringsEncrypted)
                .append(" rewrites=").append(obfuscation.stringLoadsRewritten)
                .append(" opaque-predicates=").append(obfuscation.opaquePredicatesInserted)
                .append(" flattened-methods=").append(obfuscation.methodsFlattened)
                .append(" flattened-blocks=").append(obfuscation.flattenedBlocks)
                .append(" mba-substitutions=").append(obfuscation.mbaSubstitutions)
                .append('\n')
            obfuscation.decoderClass?.let { sb.append("# bytecode-string-decoder: ").append(it).append('\n') }
        }
        return sb.toString()
    }

    /**
     * Returns the R8 portion of a composed mapping (everything before the kseal
     * addendum). Used by tests to assert the original mapping is preserved intact.
     */
    fun r8PortionOf(composed: String): String {
        val marker = composed.indexOf(ADDENDUM_HEADER)
        val head = if (marker < 0) composed else composed.substring(0, marker)
        return head.trimEnd()
    }
}
