package io.kseal.gradle.internal

/**
 * The build-proof manifest: the immutable, registrable record of what a hardened
 * build is and how it was produced. It is consumed at runtime (via
 * `RegistryService.CreateBuild`) to verify binary integrity during attestation.
 *
 * The schema is platform-neutral and shared with the iOS Xcode plugin (WS-C):
 * both emit `kseal.build-proof/v1` with the same top-level shape, differing only
 * in `platform` and platform-specific transform names. See
 * `docs/build-hardening-android.md` for the authoritative schema.
 */
internal data class BuildProofManifest(
    val platform: String,
    val packageId: String,
    val versionName: String,
    val versionCode: Long,
    val sdkName: String,
    val sdkVersion: String,
    val seedDigestHex: String,
    val seedAlgorithm: String,
    val seedDerivation: String,
    val tooling: Map<String, Any?>,
    val transforms: List<TransformRecord>,
    val artifacts: List<ArtifactDigest>,
) {
    /**
     * The build hash binds the proof to the produced binary content. It is the
     * SHA-256 of the canonical "core" (app identity + sdk + seed digest +
     * transform identities + sorted artifact digests) and deliberately excludes
     * volatile fields (`created_at`, host tooling versions, registration result)
     * so it is reproducible across machines for identical inputs.
     */
    fun computeBuildHash(): String {
        val core = linkedMapOf<String, Any?>(
            "schema" to SCHEMA,
            "platform" to platform,
            "app" to appMap(),
            "sdk" to sdkMap(),
            "seed_digest" to seedDigestHex,
            "transforms" to transforms.map { linkedMapOf<String, Any?>("name" to it.name, "status" to it.status) },
            "artifacts" to artifacts.sortedBy { it.path }
                .map { linkedMapOf<String, Any?>("path" to it.path, "sha256" to it.sha256) },
        )
        return Crypto.sha256Hex(Json.write(core, indent = false).toByteArray())
    }

    /** Full manifest document, including the computed build hash and timestamp. */
    fun toJson(buildHash: String, createdAtIso: String, registration: Map<String, Any?>? = null): String =
        Json.write(toMap(buildHash, createdAtIso, registration))

    fun toMap(buildHash: String, createdAtIso: String, registration: Map<String, Any?>?): Map<String, Any?> {
        val m = linkedMapOf<String, Any?>(
            "schema" to SCHEMA,
            "manifest_revision" to MANIFEST_REVISION,
            "platform" to platform,
            "build_hash" to buildHash,
            "created_at" to createdAtIso,
            "app" to appMap(),
            "sdk" to sdkMap(),
            "seed" to linkedMapOf<String, Any?>(
                "digest" to seedDigestHex,
                "algorithm" to seedAlgorithm,
                "derivation" to seedDerivation,
            ),
            "tooling" to tooling,
            "transforms" to transforms.map { it.toMap() },
            "artifacts" to artifacts.sortedBy { it.path }
                .map { linkedMapOf<String, Any?>("path" to it.path, "sha256" to it.sha256) },
            // v2 additive sections (backward-compatible: schema id is unchanged
            // and the build_hash core is untouched; consumers that don't know
            // these keys simply ignore them).
            "hash_coverage" to hashCoverage(buildHash),
            "reproducibility" to reproducibility(),
        )
        if (registration != null) m["registration"] = registration
        return m
    }

    /**
     * Explicit, auditable description of exactly what the build hash binds. The
     * `artifacts_root` is an independent SHA-256 over the sorted
     * `path\u0000sha256` lines, so a verifier holding the hardened artifacts can
     * recompute it and confirm the manifest covers precisely that artifact set
     * (no silent gaps). `by_category` surfaces per-plane file counts.
     */
    private fun hashCoverage(buildHash: String): Map<String, Any?> {
        val sorted = artifacts.sortedBy { it.path }
        val root = Crypto.sha256Hex(sorted.joinToString("\n") { "${it.path}\u0000${it.sha256}" }.toByteArray())
        val byCategory = sorted.groupingBy { it.path.substringBefore('/') }.eachCount().toSortedMap()
        return linkedMapOf(
            "algorithm" to "sha256",
            "artifact_count" to sorted.size,
            "by_category" to LinkedHashMap(byCategory),
            "artifacts_root" to root,
            "build_hash" to buildHash,
            // The build hash binds these manifest regions; documented so a
            // verifier knows which fields are integrity-protected vs. advisory.
            "covered_fields" to listOf("schema", "platform", "app", "sdk", "seed_digest", "transforms", "artifacts"),
            "complete" to sorted.isNotEmpty(),
        )
    }

    /**
     * Reproducibility posture. A build is byte-for-byte reproducible from
     * identical inputs unless the per-build seed was randomized (observe-only
     * max-polymorphism mode), in which case it is intentionally non-reproducible.
     */
    private fun reproducibility(): Map<String, Any?> = linkedMapOf(
        "reproducible" to (seedDerivation != "random"),
        "seed_derivation" to seedDerivation,
        "build_hash_algorithm" to "sha256",
    )

    private fun appMap() = linkedMapOf<String, Any?>(
        "package_id" to packageId,
        "version_name" to versionName,
        "version_code" to versionCode,
    )

    private fun sdkMap() = linkedMapOf<String, Any?>(
        "name" to sdkName,
        "version" to sdkVersion,
    )

    companion object {
        const val SCHEMA = "kseal.build-proof/v1"

        /**
         * Additive content revision within the v1 schema. Bumped to 2 when the
         * `hash_coverage`/`reproducibility` sections were added; the `schema`
         * identifier is unchanged so existing consumers keep validating.
         */
        const val MANIFEST_REVISION = 2
    }
}

internal data class ArtifactDigest(val path: String, val sha256: String)

internal data class TransformRecord(
    val name: String,
    val status: String,
    val details: Map<String, Any?> = emptyMap(),
) {
    fun toMap(): Map<String, Any?> = linkedMapOf(
        "name" to name,
        "status" to status,
        "details" to details,
    )
}
