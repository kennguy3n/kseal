package io.kseal.gradle

import java.io.File
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

/**
 * End-to-end: the optional MASVS report task shells out to the real
 * `tools/masvs-report` generator after hardening and emits a report that
 * reflects this build's manifest. Skipped when the Go toolchain is unavailable
 * (the generator is a separate tool the plugin only invokes when configured).
 */
class MasvsReportFunctionalTest {

    @TempDir
    lateinit var projectDir: File

    private fun runner(vararg args: String): GradleRunner =
        GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments(*args, "--stacktrace")
            .forwardOutput()

    private fun goAvailable(): Boolean = try {
        ProcessBuilder("go", "version").redirectErrorStream(true).start().waitFor() == 0
    } catch (e: Exception) {
        false
    }

    private fun buildGenerator(): File {
        val moduleDir = File(System.getProperty("user.dir"))
        val toolSrc = File(moduleDir, "../../tools/masvs-report").canonicalFile
        assertTrue(toolSrc.isDirectory, "masvs-report sources must exist at $toolSrc")
        val out = File(projectDir, "masvs-report.bin")
        val proc = ProcessBuilder("go", "build", "-o", out.absolutePath, ".")
            .directory(toolSrc)
            .redirectErrorStream(true)
            .start()
        val log = proc.inputStream.bufferedReader().readText()
        assertEquals(0, proc.waitFor(), "go build failed:\n$log")
        return out
    }

    private val catalog = """
        # MASVS mapping

        ## MASVS-CODE

        Objective: code quality.

        | MASVS objective | kseal control | Phase | Module | MASTG |
        |---|---|---|---|---|
        | Memory safety in native | Rust core; CFI/MTE where supported | P1/P3 | build hardening | CFI/MTE present |
        | Build provenance | Build proof records hashes | P3 | build proof | unregistered build flagged |

        ## MASVS-RESILIENCE

        Objective: resilience.

        | MASVS objective | kseal control | Phase | Module | MASTG |
        |---|---|---|---|---|
        | Obfuscation + polymorphism | Per-build polymorphic obfuscation | P3 | build plane | diff two builds |
        | Anti-tamper / integrity | App-integrity + build-proof binding | P2/P3 | modules | patch binary |
    """.trimIndent()

    @Test
    fun `report task emits evidence reflecting the build manifest`() {
        assumeTrue(goAvailable(), "Go toolchain unavailable; skipping masvs-report integration")
        val generator = buildGenerator()
        File(projectDir, "masvs-mapping.md").writeText(catalog)

        File(projectDir, "settings.gradle.kts").writeText("rootProject.name = \"masvs-fixture\"\n")
        File(projectDir, "build.gradle.kts").writeText(
            """
            plugins { id("io.kseal.android.harden") }

            ksealHarden {
                injectSdk.set(false)
                packageId.set("com.example.masvs")
                versionName.set("1.0.0")
                versionCode.set(100L)
                nativeLibsDirs.from(layout.projectDirectory.dir("jniLibs"))
                polymorphism { explicitSeedHex.set("${"ab".repeat(32)}") }
                registry { offline.set(true) }
                masvsReport {
                    enabled.set(true)
                    executable.set("${generator.absolutePath.replace("\\", "/")}")
                    catalogFile.set(layout.projectDirectory.file("masvs-mapping.md"))
                }
            }
            """.trimIndent(),
        )
        // A native lib so the CODE/native control is evidenced.
        File(projectDir, "jniLibs/arm64-v8a").mkdirs()
        File(projectDir, "jniLibs/arm64-v8a/libx.so").writeBytes(minimalAarch64Elf())

        val result = runner("ksealHarden").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":ksealMasvsReport")?.outcome)

        val md = File(projectDir, "build/kseal/reports/masvs-evidence.md")
        val json = File(projectDir, "build/kseal/reports/masvs-evidence.json")
        assertTrue(md.isFile, "markdown report must be written")
        assertTrue(json.isFile, "json report must be written")

        val mdText = md.readText()
        assertTrue(mdText.contains("MASVS-RESILIENCE"))
        assertTrue(mdText.contains("evidenced"), "at least one control must be evidenced from the manifest")

        val jsonText = json.readText()
        assertTrue(jsonText.contains("\"platform\": \"android\""))
        assertTrue(jsonText.contains("\"evidencedControls\""))
        assertTrue(jsonText.contains("Build provenance") || jsonText.contains("provenance"))
    }

    // Minimal 64-bit ELF (aarch64) sufficient for ElfInspector to classify arch.
    private fun minimalAarch64Elf(): ByteArray {
        val b = ByteArray(64)
        b[0] = 0x7f; b[1] = 'E'.code.toByte(); b[2] = 'L'.code.toByte(); b[3] = 'F'.code.toByte()
        b[4] = 2 // ELFCLASS64
        b[5] = 1 // little endian
        b[6] = 1 // version
        b[16] = 3 // ET_DYN (lo byte of e_type)
        b[18] = 183.toByte() // EM_AARCH64 (lo byte of e_machine)
        return b
    }
}
