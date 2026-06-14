package io.kseal.gradle.tasks

import io.kseal.gradle.internal.BytecodeObfuscator
import io.kseal.gradle.internal.Crypto
import io.kseal.gradle.internal.Json
import io.kseal.gradle.internal.ObfuscationStrength
import java.io.File
import org.gradle.api.DefaultTask
import org.gradle.api.InvalidUserDataException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Classpath
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/**
 * R8/mapping-aware bytecode control-flow obfuscation pass (see [BytecodeObfuscator]).
 *
 * Runs on the debug-stripped classes, before dexing. Output is a pure function of
 * the input classes, the seed digest (carried by the seed file's content hash)
 * and the configured strength, so the task is cacheable and reproducible while
 * still producing per-build-distinct bytecode when the seed changes.
 *
 * When [strength] is `OFF` the classes are copied through unchanged, so the pass
 * is fully fail-safe and default-off.
 */
@CacheableTask
abstract class ObfuscateBytecodeTask : DefaultTask() {

    @get:Classpath
    abstract val classesDir: DirectoryProperty

    /** Seed file; its content hash keys the cache, so a new seed re-keys the transforms. */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val seedFile: RegularFileProperty

    @get:Input
    abstract val strength: Property<String>

    /** Exact string literals never encrypted (e.g. reflection/resource lookup keys). */
    @get:Input
    abstract val keepStrings: ListProperty<String>

    @get:OutputDirectory
    abstract val obfuscatedClassesDir: DirectoryProperty

    @get:OutputFile
    abstract val reportFile: RegularFileProperty

    @TaskAction
    fun run() {
        val outDir = obfuscatedClassesDir.get().asFile
        outDir.deleteRecursively()
        outDir.mkdirs()

        val root = classesDir.get().asFile
        val configured = strength.getOrElse(ObfuscationStrength.LOW.name)
        val strengthLevel = try {
            ObfuscationStrength.parseStrict(configured)
        } catch (e: IllegalArgumentException) {
            throw InvalidUserDataException(
                "kseal: invalid ksealHarden { obfuscation { strength } } — ${e.message}",
                e,
            )
        }

        // Partition inputs: .class files are obfuscated, everything else copied through.
        val classFiles = LinkedHashMap<String, ByteArray>()
        var copied = 0
        if (root.isDirectory) {
            root.walkTopDown().filter { it.isFile }.forEach { file ->
                val rel = root.toPath().relativize(file.toPath()).toString().replace(File.separatorChar, '/')
                if (isClassFile(file.name)) {
                    classFiles[rel] = file.readBytes()
                } else {
                    val target = File(outDir, rel)
                    target.parentFile?.mkdirs()
                    file.copyTo(target, overwrite = true)
                    copied++
                }
            }
        }

        val report: BytecodeObfuscator.Summary
        if (strengthLevel == ObfuscationStrength.OFF) {
            for ((rel, bytes) in classFiles) writeClass(outDir, rel, bytes)
            report = BytecodeObfuscator.Summary(classFiles.size, 0, 0, 0, 0, null)
        } else {
            val seed = Crypto.unhex(seedFile.get().asFile.readText().trim())
            val options = strengthLevel.toOptions(keepStrings.getOrElse(emptyList()).toSet())
            val result = BytecodeObfuscator(seed, options).obfuscate(classFiles)
            for ((rel, bytes) in result.transformedClasses) writeClass(outDir, rel, bytes)
            result.decoderClass?.let { (rel, bytes) -> writeClass(outDir, rel, bytes) }
            report = result.summary
        }

        reportFile.get().asFile.writeText(
            Json.write(
                linkedMapOf<String, Any?>(
                    "transform" to "bytecode-control-flow-obfuscation",
                    "status" to if (strengthLevel == ObfuscationStrength.OFF) "disabled" else "applied",
                    "strength" to strengthLevel.name.lowercase(),
                    "classes_processed" to report.classesProcessed,
                    "files_copied" to copied,
                    "unique_strings_encrypted" to report.uniqueStringsEncrypted,
                    "string_loads_rewritten" to report.stringLoadsRewritten,
                    "methods_with_opaque_predicate" to report.methodsWithOpaquePredicate,
                    "opaque_predicates_inserted" to report.opaquePredicatesInserted,
                    "decoder_class" to report.decoderClassInternalName,
                ),
            ),
        )
        logger.lifecycle(
            "kseal: bytecode obfuscation [${strengthLevel.name.lowercase()}] " +
                "rewrote ${report.stringLoadsRewritten} string load(s), " +
                "inserted ${report.opaquePredicatesInserted} opaque predicate(s)",
        )
    }

    private fun writeClass(outDir: File, rel: String, bytes: ByteArray) {
        val target = File(outDir, rel)
        target.parentFile?.mkdirs()
        target.writeBytes(bytes)
    }

    private fun isClassFile(name: String): Boolean =
        name.endsWith(".class", ignoreCase = true) && !name.endsWith("module-info.class")
}
