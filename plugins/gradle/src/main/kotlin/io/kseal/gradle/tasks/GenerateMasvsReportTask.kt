package io.kseal.gradle.tasks

import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import org.gradle.work.DisableCachingByDefault

/**
 * Optional post-hardening step that runs the standalone `masvs-report` generator
 * against this build's emitted build-proof manifest, producing a per-release
 * MASVS evidence report (Markdown + JSON).
 *
 * The generator is a separate, zero-dependency tool (`tools/masvs-report`); the
 * plugin only shells out to it when the integrator points [executable] at a
 * built binary, so a project that does not want the report pays nothing. Output
 * is a pure function of the manifest + catalog + tool, but caching is disabled
 * because the result is produced by an external process the plugin cannot
 * fingerprint.
 */
@DisableCachingByDefault(because = "Delegates report generation to an external tool the plugin cannot fingerprint")
abstract class GenerateMasvsReportTask @Inject constructor(
    private val execOperations: ExecOperations,
) : DefaultTask() {

    /** Path to the built `masvs-report` executable. */
    @get:Input
    abstract val executable: Property<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val manifestFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val catalogFile: RegularFileProperty

    /** Extra arguments appended verbatim (e.g. an alternate catalog flag). */
    @get:Input
    @get:Optional
    abstract val extraArgs: ListProperty<String>

    @get:OutputFile
    abstract val reportMarkdownFile: RegularFileProperty

    @get:OutputFile
    abstract val reportJsonFile: RegularFileProperty

    /** Assembles the generator invocation. Pure, so it is unit-testable. */
    internal fun commandLine(): List<String> = buildList {
        add(executable.get())
        add("-manifest"); add(manifestFile.get().asFile.absolutePath)
        add("-catalog"); add(catalogFile.get().asFile.absolutePath)
        add("-out-md"); add(reportMarkdownFile.get().asFile.absolutePath)
        add("-out-json"); add(reportJsonFile.get().asFile.absolutePath)
        addAll(extraArgs.getOrElse(emptyList()))
    }

    @TaskAction
    fun generate() {
        reportMarkdownFile.get().asFile.parentFile?.mkdirs()
        reportJsonFile.get().asFile.parentFile?.mkdirs()
        val args = commandLine()
        execOperations.exec { commandLine(args) }
        logger.lifecycle("kseal: MASVS evidence report written to ${reportMarkdownFile.get().asFile}")
    }
}
