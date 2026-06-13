package io.kseal.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test

class BuildProofManifestTest {

    private fun manifest(artifactHash: String = "h1") = BuildProofManifest(
        platform = "android",
        packageId = "com.example.app",
        versionName = "1.2.3",
        versionCode = 42,
        sdkName = "kseal-android",
        sdkVersion = "0.1.0",
        seedDigestHex = "seeddigest",
        seedAlgorithm = "HKDF-SHA256",
        seedDerivation = "content",
        tooling = linkedMapOf("gradle" to "8.11.1", "java" to "17"),
        transforms = listOf(TransformRecord("strip-debug-metadata", "applied")),
        artifacts = listOf(ArtifactDigest("classes/A.class", artifactHash)),
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
}
