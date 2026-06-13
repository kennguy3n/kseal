package io.kseal.gradle.tasks

import io.kseal.gradle.internal.DebugStripper
import io.kseal.gradle.internal.Json
import java.io.File
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Classpath
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

/**
 * Strips debug metadata from the app's compiled classes before dexing.
 *
 * Inputs use `@Classpath` normalization, so cache hits are insensitive to jar
 * timestamps and entry order — only the meaningful bytecode matters. Non-class
 * files in the inputs are copied through unchanged.
 */
@CacheableTask
abstract class StripDebugMetadataTask : DefaultTask() {

    @get:Classpath
    abstract val classes: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val strippedClassesDir: DirectoryProperty

    @get:OutputFile
    abstract val reportFile: RegularFileProperty

    @TaskAction
    fun strip() {
        val outDir = strippedClassesDir.get().asFile
        outDir.deleteRecursively()
        outDir.mkdirs()

        var classCount = 0
        var copyCount = 0
        for (root in classes.files) {
            if (!root.exists()) continue
            if (root.isDirectory) {
                root.walkTopDown().filter { it.isFile }.forEach { file ->
                    val rel = root.toPath().relativize(file.toPath()).toString()
                    val target = File(outDir, rel)
                    target.parentFile?.mkdirs()
                    if (DebugStripper.isClassFile(file.name)) {
                        target.writeBytes(DebugStripper.strip(file.readBytes()))
                        classCount++
                    } else {
                        file.copyTo(target, overwrite = true)
                        copyCount++
                    }
                }
            } else if (DebugStripper.isClassFile(root.name)) {
                File(outDir, root.name).writeBytes(DebugStripper.strip(root.readBytes()))
                classCount++
            } else {
                root.copyTo(File(outDir, root.name), overwrite = true)
                copyCount++
            }
        }

        reportFile.get().asFile.writeText(
            Json.write(
                linkedMapOf<String, Any?>(
                    "transform" to "strip-debug-metadata",
                    "classes_stripped" to classCount,
                    "files_copied" to copyCount,
                ),
            ),
        )
        logger.lifecycle("kseal: stripped debug metadata from $classCount class(es)")
    }
}
