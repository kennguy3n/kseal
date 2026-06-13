package io.kseal.gradle.tasks

import io.kseal.gradle.internal.ArtifactDigest
import io.kseal.gradle.internal.BuildProofManifest
import io.kseal.gradle.internal.Hashing
import io.kseal.gradle.internal.Json
import io.kseal.gradle.internal.TransformRecord
import java.time.Instant
import java.time.format.DateTimeFormatter
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/**
 * Assembles the build-proof manifest and computes the build hash.
 *
 * Cacheable: the manifest body is a pure function of the declared inputs. The
 * `created_at` timestamp is `@Internal` (wall clock at execution) and therefore
 * does not participate in up-to-date checks — on an unchanged re-run the task is
 * skipped and the prior timestamp is preserved. `created_at` is also excluded
 * from the build hash, so identical inputs produce an identical, reproducible
 * `build_hash` across machines (see [BuildProofManifest.computeBuildHash]).
 */
@CacheableTask
abstract class BuildProofManifestTask : DefaultTask() {

    @get:Input
    abstract val platform: Property<String>

    @get:Input
    abstract val packageId: Property<String>

    @get:Input
    abstract val versionName: Property<String>

    @get:Input
    abstract val versionCode: Property<Long>

    @get:Input
    abstract val sdkName: Property<String>

    @get:Input
    abstract val sdkVersion: Property<String>

    @get:Input
    abstract val pluginVersion: Property<String>

    @get:Input
    abstract val gradleVersion: Property<String>

    @get:Input
    abstract val javaVersion: Property<String>

    @get:Input
    abstract val r8MappingPresent: Property<Boolean>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val seedDigestFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val seedMetaFile: RegularFileProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val transformReports: ConfigurableFileCollection

    @get:InputDirectory
    @get:Optional
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val strippedClassesDir: DirectoryProperty

    @get:InputDirectory
    @get:Optional
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val hardenedResourcesDir: DirectoryProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val sealedStringsFile: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mappingOutFile: RegularFileProperty

    @get:OutputFile
    abstract val manifestFile: RegularFileProperty

    @get:OutputFile
    abstract val buildHashFile: RegularFileProperty

    @TaskAction
    fun build() {
        val seedDigest = seedDigestFile.get().asFile.readText().trim()
        val seedMeta = Json.parse(seedMetaFile.get().asFile.readText()) as? Map<*, *> ?: emptyMap<Any, Any>()
        val derivation = (seedMeta["derivation"] as? String) ?: "content"

        val transforms = buildTransforms(derivation)
        val artifacts = collectArtifacts()

        val manifest = BuildProofManifest(
            platform = platform.get(),
            packageId = packageId.get(),
            versionName = versionName.get(),
            versionCode = versionCode.get(),
            sdkName = sdkName.get(),
            sdkVersion = sdkVersion.get(),
            seedDigestHex = seedDigest,
            seedAlgorithm = "HKDF-SHA256",
            seedDerivation = derivation,
            tooling = linkedMapOf(
                "plugin" to "io.kseal.android.harden:${pluginVersion.get()}",
                "gradle" to gradleVersion.get(),
                "java" to javaVersion.get(),
                "asm" to org.objectweb.asm.Opcodes::class.java.`package`.implementationVersion.orEmpty(),
                "r8_mapping" to r8MappingPresent.get(),
            ),
            transforms = transforms,
            artifacts = artifacts,
        )

        val buildHash = manifest.computeBuildHash()
        val createdAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now().let { Instant.ofEpochSecond(it.epochSecond) })
        manifestFile.get().asFile.writeText(manifest.toJson(buildHash, createdAt))
        buildHashFile.get().asFile.writeText(buildHash)
        logger.lifecycle("kseal: build-proof manifest written (build_hash=${buildHash.take(16)}…, ${artifacts.size} artifacts)")
    }

    private fun buildTransforms(derivation: String): List<TransformRecord> {
        val records = mutableListOf(
            TransformRecord(
                name = "polymorphism",
                status = "applied",
                details = linkedMapOf("algorithm" to "HKDF-SHA256", "derivation" to derivation),
            ),
        )
        for (report in transformReports.files.filter { it.isFile }.sortedBy { it.name }) {
            val obj = Json.parse(report.readText()) as? Map<*, *> ?: continue
            val name = obj["transform"] as? String ?: continue
            val details = obj.entries
                .filter { it.key != "transform" }
                .associate { (it.key as String) to it.value }
            records.add(TransformRecord(name = name, status = "applied", details = details))
        }
        return records.sortedBy { it.name }
    }

    private fun collectArtifacts(): List<ArtifactDigest> {
        val out = mutableListOf<ArtifactDigest>()
        strippedClassesDir.orNull?.asFile?.let { out += Hashing.artifactDigests(it, "classes") }
        hardenedResourcesDir.orNull?.asFile?.let { out += Hashing.artifactDigests(it, "res") }
        sealedStringsFile.orNull?.asFile?.takeIf { it.isFile }
            ?.let { out += ArtifactDigest("assets/kseal/strings.sealed", Hashing.sha256(it)) }
        mappingOutFile.orNull?.asFile?.takeIf { it.isFile }
            ?.let { out += ArtifactDigest("mapping.txt", Hashing.sha256(it)) }
        return out.sortedBy { it.path }
    }
}
