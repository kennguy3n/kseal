package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BuildProofManifestTest {

    private fun manifest(
        artifactHash: String = "h1",
        seedDerivation: String = "content",
        artifacts: List<ArtifactDigest> = listOf(ArtifactDigest("classes/A.class", artifactHash)),
        transforms: List<TransformRecord> = listOf(TransformRecord("strip-debug-metadata", "applied")),
    ) = BuildProofManifest(
        platform = "android",
        packageId = "com.example.app",
        versionName = "1.2.3",
        versionCode = 42,
        sdkName = "kseal-android",
        sdkVersion = "0.1.0",
        seedDigestHex = "seeddigest",
        seedAlgorithm = "HKDF-SHA256",
        seedDerivation = seedDerivation,
        tooling = linkedMapOf("gradle" to "8.11.1", "java" to "17"),
        transforms = transforms,
        artifacts = artifacts,
    )

    @Test
    fun `build hash is stable and independent of created_at`() {
        val m = manifest()
        val hash = m.computeBuildHash()
        val j1 = m.toJson(hash, "2020-01-01T00:00:00Z")
        val j2 = m.toJson(hash, "2099-12-31T23:59:59Z")
        // created_at differs, build_hash does not.
        @Suppress("UNCHECKED_CAST")
        val p1 = Json.parse(j1) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val p2 = Json.parse(j2) as Map<String, Any?>
        assertEquals(p1["build_hash"], p2["build_hash"])
        assertNotEquals(p1["created_at"], p2["created_at"])
        assertEquals(hash, p1["build_hash"])
    }

    @Test
    fun `build hash changes with artifact content`() {
        assertNotEquals(manifest("h1").computeBuildHash(), manifest("h2").computeBuildHash())
    }

    @Test
    fun `skipped selective virtualization does not change default build hash`() {
        val base = manifest()
        val withSkippedVirtualization = manifest(
            transforms = listOf(
                TransformRecord("strip-debug-metadata", "applied"),
                TransformRecord("selective-virtualization", "skipped"),
            ),
        )
        assertEquals(base.computeBuildHash(), withSkippedVirtualization.computeBuildHash())

        val appliedVirtualization = manifest(
            transforms = listOf(
                TransformRecord("strip-debug-metadata", "applied"),
                TransformRecord("selective-virtualization", "applied"),
            ),
        )
        assertNotEquals(base.computeBuildHash(), appliedVirtualization.computeBuildHash())
    }

    @Test
    fun `manifest carries the expected top level fields`() {
        val m = manifest()
        @Suppress("UNCHECKED_CAST")
        val doc = Json.parse(m.toJson(m.computeBuildHash(), "2020-01-01T00:00:00Z")) as Map<String, Any?>
        assertEquals("kseal.build-proof/v1", doc["schema"])
        assertEquals("android", doc["platform"])
        @Suppress("UNCHECKED_CAST")
        val app = doc["app"] as Map<String, Any?>
        assertEquals("com.example.app", app["package_id"])
        assertEquals(42L, app["version_code"])
        @Suppress("UNCHECKED_CAST")
        val seed = doc["seed"] as Map<String, Any?>
        assertEquals("HKDF-SHA256", seed["algorithm"])
    }

    @Test
    fun `v2 sections are additive and do not affect the build hash`() {
        // The build hash core excludes hash_coverage/reproducibility, so the hash
        // is unchanged from the v1 computation and stays reproducible.
        val m = manifest()
        val hash = m.computeBuildHash()
        @Suppress("UNCHECKED_CAST")
        val doc = Json.parse(m.toJson(hash, "2020-01-01T00:00:00Z")) as Map<String, Any?>
        // v1 schema id preserved; revision marker bumped.
        assertEquals("kseal.build-proof/v1", doc["schema"])
        assertEquals(2L, doc["manifest_revision"])
        assertEquals(hash, doc["build_hash"])
    }

    @Test
    fun `hash coverage records an independently verifiable artifacts root`() {
        val artifacts = listOf(
            ArtifactDigest("res/values/strings.xml", "aaaa"),
            ArtifactDigest("classes/A.class", "bbbb"),
            ArtifactDigest("mapping.txt", "cccc"),
        )
        val m = manifest(artifacts = artifacts)
        @Suppress("UNCHECKED_CAST")
        val doc = Json.parse(m.toJson(m.computeBuildHash(), "2020-01-01T00:00:00Z")) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val coverage = doc["hash_coverage"] as Map<String, Any?>

        assertEquals(3L, coverage["artifact_count"])
        assertEquals(true, coverage["complete"])
        @Suppress("UNCHECKED_CAST")
        val byCategory = coverage["by_category"] as Map<String, Any?>
        assertEquals(1L, byCategory["classes"])
        assertEquals(1L, byCategory["res"])
        assertEquals(1L, byCategory["mapping.txt"])

        // A verifier holding the artifacts can recompute the root identically.
        val expectedRoot = Crypto.sha256Hex(
            artifacts.sortedBy { it.path }.joinToString("\n") { "${it.path}\u0000${it.sha256}" }.toByteArray(),
        )
        assertEquals(expectedRoot, coverage["artifacts_root"])
    }

    @Test
    fun `reproducibility reflects the seed derivation`() {
        @Suppress("UNCHECKED_CAST")
        val content = Json.parse(manifest().toJson("x", "t")) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val repro = content["reproducibility"] as Map<String, Any?>
        assertTrue(repro["reproducible"] as Boolean)
        assertEquals("content", repro["seed_derivation"])

        @Suppress("UNCHECKED_CAST")
        val randomDoc = Json.parse(manifest(seedDerivation = "random").toJson("x", "t")) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val randomRepro = randomDoc["reproducibility"] as Map<String, Any?>
        assertFalse(randomRepro["reproducible"] as Boolean)
    }
}
