package io.kseal.gradle.tasks

import io.kseal.gradle.internal.ElfInspector
import io.kseal.gradle.internal.Json
import io.kseal.gradle.internal.NativeStringObfuscationInspector
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
        // Every feature is tallied across all four verification outcomes so the
        // aggregate is complete and honest: `unsupported` (cannot apply to the ABI)
        // is reported, never silently dropped. Downstream consumers (the MASVS
        // report's evalNativeMemory) read the *_unsupported counts directly.
        val summary = linkedMapOf(
            "cfi_enabled" to 0, "cfi_absent" to 0, "cfi_unsupported" to 0,
            "mte_enabled" to 0, "mte_absent" to 0, "mte_unsupported" to 0,
            "bti_enabled" to 0, "bti_absent" to 0, "bti_unsupported" to 0,
            "pac_enabled" to 0, "pac_absent" to 0, "pac_unsupported" to 0,
            // Classic exploit-mitigation posture, tallied across the same four outcomes.
            "relro_enabled" to 0, "relro_absent" to 0, "relro_unsupported" to 0,
            "nx_enabled" to 0, "nx_absent" to 0, "nx_unsupported" to 0,
            "pie_enabled" to 0, "pie_absent" to 0, "pie_unsupported" to 0,
            "canary_enabled" to 0, "canary_absent" to 0, "canary_unsupported" to 0,
            "fortify_enabled" to 0, "fortify_absent" to 0, "fortify_unsupported" to 0,
            "indeterminate" to 0,
            // Phase 5.2 string-obfuscation posture, recorded only for the kseal
            // trust core itself (third-party .so's are `not_applicable`).
            "string_obfuscation_obfuscated" to 0,
            "string_obfuscation_plaintext" to 0,
            "string_obfuscation_not_applicable" to 0,
            "string_obfuscation_indeterminate" to 0,
        )

        for ((logicalPath, file) in collectLibraries().toSortedMap()) {
            val result = ElfInspector.inspect(file)
            file.copyTo(File(outDir, logicalPath).also { it.parentFile?.mkdirs() }, overwrite = true)

            tally(summary, "cfi", result.cfi)
            tally(summary, "mte", result.mte)
            tally(summary, "bti", result.bti)
            tally(summary, "pac", result.pac)
            tally(summary, "relro", result.relro)
            tally(summary, "nx", result.nx)
            tally(summary, "pie", result.pie)
            tally(summary, "canary", result.stackCanary)
            tally(summary, "fortify", result.fortify)
            if (result.cfi == ElfInspector.Status.INDETERMINATE) summary["indeterminate"] = summary.getValue("indeterminate") + 1

            val strings = NativeStringObfuscationInspector.inspect(file)
            val stringsKey = "string_obfuscation_${strings.status.name.lowercase()}"
            summary[stringsKey] = summary.getValue(stringsKey) + 1

            libraries += linkedMapOf<String, Any?>(
                "path" to logicalPath,
                "arch" to result.arch.id,
                "sha256" to result.sha256,
                "cfi" to result.cfi.wire,
                "mte" to result.mte.wire,
                "bti" to result.bti.wire,
                "pac" to result.pac.wire,
                "mte_mode" to result.mteMode,
                "relro" to result.relro.wire,
                "relro_mode" to result.relroMode,
                "nx" to result.nx.wire,
                "pie" to result.pie.wire,
                "stack_canary" to result.stackCanary.wire,
                "fortify" to result.fortify.wire,
                "fully_hardened" to result.fullyHardened,
                "mitigations_complete" to result.mitigationsComplete,
                "notes" to result.notes,
                "posture_notes" to result.postureNotes,
                "string_obfuscation" to strings.status.wire,
                "string_markers" to strings.markersFound,
                "string_notes" to strings.notes,
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
            val findings = listOf("cfi", "mte", "bti", "pac", "relro", "nx", "pie", "canary", "fortify")
                .sumOf { summary.getValue("${it}_absent") }
            logger.lifecycle(
                "kseal: verified ${libraries.size} native librar${if (libraries.size == 1) "y" else "ies"} " +
                    "(cfi=${summary["cfi_enabled"]} mte=${summary["mte_enabled"]} relro=${summary["relro_enabled"]} " +
                    "nx=${summary["nx_enabled"]} pie=${summary["pie_enabled"]}${if (findings > 0) ", $findings finding(s)" else ""})",
            )
        }
    }

    private fun tally(summary: MutableMap<String, Int>, feature: String, status: ElfInspector.Status) {
        val key = when (status) {
            ElfInspector.Status.ENABLED -> "${feature}_enabled"
            ElfInspector.Status.ABSENT -> "${feature}_absent"
            ElfInspector.Status.UNSUPPORTED -> "${feature}_unsupported"
            ElfInspector.Status.INDETERMINATE -> return
        }
        summary[key] = summary.getValue(key) + 1
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
