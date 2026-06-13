package io.kseal.gradle.tasks

import io.kseal.gradle.internal.Crypto
import io.kseal.gradle.internal.Json
import io.kseal.gradle.internal.KeepRules
import io.kseal.gradle.internal.MappingComposer
import io.kseal.gradle.internal.ResourceHardener
import java.io.File
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/**
 * R8-aware string-resource obfuscation pass.
 *
 * Cacheable and reproducible: output is a pure function of the resources, keep
 * rules and the seed digest (carried via the seed file content hash). Re-running
 * with unchanged inputs is `UP-TO-DATE`; a changed seed (new build content)
 * re-keys the seal and re-permutes the tokens, delivering per-build polymorphism.
 */
@CacheableTask
abstract class HardenResourcesTask : DefaultTask() {

    @get:InputDirectory
    @get:Optional
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val resourcesDir: DirectoryProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mappingFile: RegularFileProperty

    /**
     * Optional bytecode-obfuscation report (from `ksealObfuscateBytecode`). When
     * the pass applied, its structural summary is recorded in the mapping
     * addendum so the addendum fully describes what kseal did to the build.
     */
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val obfuscationReportFile: RegularFileProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val keepRuleFiles: ConfigurableFileCollection

    @get:Input
    abstract val keepStringKeys: ListProperty<String>

    /** Seed file; its content hash keys the cache, so a new seed busts the cache. */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val seedFile: RegularFileProperty

    @get:OutputDirectory
    abstract val hardenedResourcesDir: DirectoryProperty

    @get:OutputFile
    abstract val sealedStringsFile: RegularFileProperty

    @get:OutputFile
    abstract val mappingOutFile: RegularFileProperty

    @get:OutputFile
    abstract val reportFile: RegularFileProperty

    @TaskAction
    fun harden() {
        val outDir = hardenedResourcesDir.get().asFile
        outDir.deleteRecursively()
        outDir.mkdirs()

        val seed = Crypto.unhex(seedFile.get().asFile.readText().trim())
        val keep = KeepRules.parse(
            ruleText = keepRuleFiles.files.filter { it.isFile }.joinToString("\n") { it.readText() },
            extraNameGlobs = keepStringKeys.getOrElse(emptyList()),
        )

        val resDir = resourcesDir.orNull?.asFile
        val resFiles: List<ResourceHardener.ResFile>
        if (resDir != null && resDir.isDirectory) {
            // Mirror the whole resource tree so the output is a drop-in replacement,
            // then overwrite the values-dir string files with hardened versions.
            resDir.copyRecursively(outDir, overwrite = true)
            resFiles = resDir.walkTopDown()
                .filter { it.isFile && it.extension.equals("xml", true) && it.parentFile.name.startsWith("values") }
                .filter { it.readText().contains("<string") }
                .map { ResourceHardener.ResFile(resDir.toPath().relativize(it.toPath()).toString(), it.readText()) }
                .toList()
        } else {
            resFiles = emptyList()
        }

        val result = ResourceHardener.harden(resFiles, keep, seed)
        for ((rel, content) in result.transformedFiles) {
            val target = File(outDir, rel)
            target.parentFile?.mkdirs()
            target.writeText(content)
        }

        val sealed = sealedStringsFile.get().asFile
        sealed.parentFile?.mkdirs()
        sealed.writeBytes(result.sealedBlob)

        val seedDigest = Crypto.sha256Hex(seed)
        mappingOutFile.get().asFile.writeText(
            MappingComposer.compose(
                r8Mapping = mappingFile.orNull?.asFile?.takeIf { it.isFile }?.readText(),
                seedDigestHex = seedDigest,
                resourceTokens = result.tokenToKey,
                obfuscation = readObfuscationSummary(),
            ),
        )

        reportFile.get().asFile.writeText(
            Json.write(
                linkedMapOf<String, Any?>(
                    "transform" to "string-resource-seal",
                    "sealed_count" to result.sealedCount,
                    "kept_count" to result.keptCount,
                    "tokens" to result.tokenToKey,
                ),
            ),
        )
        logger.lifecycle("kseal: sealed ${result.sealedCount} string(s), kept ${result.keptCount} in clear")
    }

    /**
     * Parses the optional obfuscation report into a mapping-addendum summary.
     * Returns null unless the pass actually applied, so the default (obfuscation
     * disabled) build emits a byte-identical mapping.
     */
    private fun readObfuscationSummary(): MappingComposer.Obfuscation? {
        val file = obfuscationReportFile.orNull?.asFile?.takeIf { it.isFile } ?: return null
        val root = Json.parse(file.readText()) as? Map<*, *> ?: return null
        if (root["status"] != "applied") return null
        fun int(key: String): Int = (root[key] as? Number)?.toInt() ?: 0
        return MappingComposer.Obfuscation(
            strength = root["strength"]?.toString() ?: "low",
            decoderClass = root["decoder_class"]?.toString(),
            uniqueStringsEncrypted = int("unique_strings_encrypted"),
            stringLoadsRewritten = int("string_loads_rewritten"),
            opaquePredicatesInserted = int("opaque_predicates_inserted"),
        )
    }
}
