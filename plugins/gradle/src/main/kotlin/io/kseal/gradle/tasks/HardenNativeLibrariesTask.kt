package io.kseal.gradle.tasks

import io.kseal.gradle.internal.ElfInspector
import io.kseal.gradle.internal.Json
import java.io.File
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

/**
 * Verifies and records the native-hardening posture of every shipped `.so`.
 *
 * CFI/MTE (and the AArch64 branch-protection features BTI/PAC) are produced by
 * the NDK toolchain at compile/link time; this task does not — and cannot —
 * inject them after linking. Instead it parses each library's ELF structure to
 * confirm the hardening markers are present, records a per-library status plus a
 * content hash into the build-proof manifest, and surfaces any library that is
 * *missing* a feature its ABI supports as a finding (`absent`) rather than
 * silently skipping it. Features that cannot apply to a target (e.g. MTE on a
 * 32-bit/x86 ABI) are reported as `unsupported`.
 *
 * Cacheable: the result is a pure function of the input `.so` bytes. Libraries
 * are copied verbatim into [hardenedNativeDir] so their content digests join the
 * manifest's `artifacts` list (and therefore bind into the reproducible
 * `build_hash`).
 */
@CacheableTask
abstract class HardenNativeLibrariesTask : DefaultTask() {

    /** Roots that contain native libraries (e.g. merged `jniLibs` / `<abi>/lib*.so`). */
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val nativeLibDirs: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val hardenedNativeDir: DirectoryProperty

    @get:OutputFile
    abstract val reportFile: RegularFileProperty

    @TaskAction
    fun harden() {
        val outDir = hardenedNativeDir.get().asFile
        outDir.deleteRecursively()
        outDir.mkdirs()

        val libraries = mutableListOf<Map<String, Any?>>()
        val summary = linkedMapOf(
            "cfi_enabled" to 0, "cfi_absent" to 0,
            "mte_enabled" to 0, "mte_absent" to 0,
            "bti_enabled" to 0, "pac_enabled" to 0,
            "indeterminate" to 0,
        )

        for ((logicalPath, file) in collectLibraries().toSortedMap()) {
            val result = ElfInspector.inspect(file)
            file.copyTo(File(outDir, logicalPath).also { it.parentFile?.mkdirs() }, overwrite = true)

            tally(summary, "cfi", result.cfi)
            tally(summary, "mte", result.mte)
            if (result.bti == ElfInspector.Status.ENABLED) summary["bti_enabled"] = summary.getValue("bti_enabled") + 1
            if (result.pac == ElfInspector.Status.ENABLED) summary["pac_enabled"] = summary.getValue("pac_enabled") + 1
            if (result.cfi == ElfInspector.Status.INDETERMINATE) summary["indeterminate"] = summary.getValue("indeterminate") + 1

            libraries += linkedMapOf<String, Any?>(
                "path" to logicalPath,
                "arch" to result.arch.id,
                "sha256" to result.sha256,
                "cfi" to result.cfi.wire,
                "mte" to result.mte.wire,
                "bti" to result.bti.wire,
                "pac" to result.pac.wire,
                "mte_mode" to result.mteMode,
                "fully_hardened" to result.fullyHardened,
                "notes" to result.notes,
            )
        }

        val report = linkedMapOf<String, Any?>(
            "transform" to "native-library-harden",
            "status" to if (libraries.isEmpty()) "skipped" else "applied",
            "library_count" to libraries.size,
            "summary" to summary,
            "libraries" to libraries,
        )
        reportFile.get().asFile.writeText(Json.write(report))

        if (libraries.isEmpty()) {
            logger.lifecycle("kseal: no native libraries to harden")
        } else {
            val absent = (summary.getValue("cfi_absent") + summary.getValue("mte_absent"))
            logger.lifecycle(
                "kseal: verified ${libraries.size} native librar${if (libraries.size == 1) "y" else "ies"} " +
                    "(cfi=${summary["cfi_enabled"]} mte=${summary["mte_enabled"]}${if (absent > 0) ", $absent finding(s)" else ""})",
            )
        }
    }

    private fun tally(summary: MutableMap<String, Int>, feature: String, status: ElfInspector.Status) {
        when (status) {
            ElfInspector.Status.ENABLED -> summary["${feature}_enabled"] = summary.getValue("${feature}_enabled") + 1
            ElfInspector.Status.ABSENT -> summary["${feature}_absent"] = summary.getValue("${feature}_absent") + 1
            else -> Unit
        }
    }

    /** Maps each `.so` to a stable logical path (`<abi>/libfoo.so`), de-duplicated by path. */
    private fun collectLibraries(): Map<String, File> {
        val out = linkedMapOf<String, File>()
        for (root in nativeLibDirs.files) {
            if (!root.exists()) continue
            if (root.isFile) {
                if (root.name.endsWith(".so")) out.putIfAbsent(root.name, root)
                continue
            }
            root.walkTopDown()
                .filter { it.isFile && it.name.endsWith(".so") }
                .forEach { f ->
                    val rel = root.toPath().relativize(f.toPath()).toString().replace(File.separatorChar, '/')
                    out.putIfAbsent(rel, f)
                }
        }
        return out
    }
}
