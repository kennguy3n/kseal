package io.kseal.gradle.tasks

import io.kseal.gradle.internal.Crypto
import io.kseal.gradle.internal.Hashing
import io.kseal.gradle.internal.Json
import io.kseal.gradle.internal.SeedDeriver
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/**
 * Generates the per-build polymorphism seed.
 *
 * Intentionally **not** `@CacheableTask`: the seed is sensitive key material and
 * must never be pushed to a shared build cache. In the default (deterministic)
 * mode the task is still locally `UP-TO-DATE` when its inputs are unchanged; in
 * `randomize` mode it is forced to re-run every build (wired in the plugin).
 *
 * Only the seed *digest* (a non-secret SHA-256) flows into downstream cache keys
 * and the manifest; the raw seed stays on disk in the build directory.
 */
abstract class GeneratePolymorphismSeedTask : DefaultTask() {

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val hardeningInputs: ConfigurableFileCollection

    @get:Input
    @get:Optional
    abstract val explicitSeedHex: Property<String>

    @get:Input
    abstract val randomize: Property<Boolean>

    @get:Input
    abstract val projectSalt: Property<String>

    /** Per-tenant master key (secret) — deliberately not a tracked input. */
    @get:Internal
    abstract val masterKeyHex: Property<String>

    @get:OutputFile
    abstract val seedFile: RegularFileProperty

    @get:OutputFile
    abstract val seedDigestFile: RegularFileProperty

    @get:OutputFile
    abstract val seedMetaFile: RegularFileProperty

    @TaskAction
    fun generate() {
        val inputsDigest = Hashing.digestOfContents(hardeningInputs.files)
        val explicit = explicitSeedHex.orNull?.takeIf { it.isNotBlank() }
        val master = masterKeyHex.orNull?.takeIf { it.isNotBlank() }
        val randomized = randomize.getOrElse(false)

        val derivation = when {
            explicit != null -> "explicit"
            randomized -> "random"
            master != null -> "master"
            else -> "content"
        }

        val seed = SeedDeriver.derive(
            SeedDeriver.Inputs(
                explicitSeedHex = explicit,
                randomize = randomized,
                masterKeyHex = master,
                projectSalt = projectSalt.get(),
                inputsDigestHex = inputsDigest,
            ),
        )

        val seedHex = Crypto.hex(seed)
        val digestHex = Crypto.sha256Hex(seed)

        writeSecret(seedFile.get().asFile, seedHex)
        seedDigestFile.get().asFile.writeText(digestHex)
        seedMetaFile.get().asFile.writeText(
            Json.write(
                linkedMapOf<String, Any?>(
                    "algorithm" to "HKDF-SHA256",
                    "derivation" to derivation,
                    "inputs_digest" to inputsDigest,
                    "seed_digest" to digestHex,
                ),
            ),
        )
        logger.lifecycle("kseal: polymorphism seed ready (derivation=$derivation, digest=${digestHex.take(16)}…)")
    }

    private fun writeSecret(file: java.io.File, content: String) {
        file.parentFile?.mkdirs()
        file.writeText(content)
        runCatching {
            Files.setPosixFilePermissions(
                file.toPath(),
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
            )
        }
    }
}
