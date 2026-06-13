package io.kseal.gradle.internal

import java.io.File

/** File-content hashing helpers shared by the seed and manifest tasks. */
internal object Hashing {

    fun sha256(file: File): String = Crypto.sha256Hex(file.readBytes())

    /**
     * A content-addressed digest of a set of files: the SHA-256 of the sorted
     * per-file content hashes. It depends only on file *contents* (not paths,
     * order or timestamps), so identical build inputs yield an identical seed on
     * any machine — the property that keeps polymorphism deterministic and the
     * hardening tasks cacheable.
     */
    fun digestOfContents(files: Iterable<File>): String {
        val hashes = files.asSequence()
            .filter { it.isFile }
            .map { sha256(it) }
            .sorted()
            .toList()
        val joined = StringBuilder().append(hashes.size).append('\n')
        hashes.forEach { joined.append(it).append('\n') }
        return Crypto.sha256Hex(joined.toString().toByteArray())
    }

    /**
     * Walks [root] and returns `(relativePath, sha256)` for every file, sorted by
     * path. [prefix] namespaces the entries within the manifest's artifact list
     * (e.g. `classes`, `res`, `assets`).
     */
    fun artifactDigests(root: File, prefix: String): List<ArtifactDigest> {
        if (!root.exists()) return emptyList()
        if (root.isFile) {
            return listOf(ArtifactDigest(prefix.ifBlank { root.name }, sha256(root)))
        }
        return root.walkTopDown()
            .filter { it.isFile }
            .map { f ->
                val rel = root.toPath().relativize(f.toPath()).toString().replace(File.separatorChar, '/')
                ArtifactDigest(if (prefix.isBlank()) rel else "$prefix/$rel", sha256(f))
            }
            .sortedBy { it.path }
            .toList()
    }
}
