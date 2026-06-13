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
 */
internal object MappingComposer {

    const val ADDENDUM_HEADER = "# kseal-build-proof mapping addendum v1"

    fun compose(
        r8Mapping: String?,
        seedDigestHex: String,
        resourceTokens: Map<String, String>,
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
