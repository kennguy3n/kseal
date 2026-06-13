package io.kseal.gradle

import java.io.File
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes

class HardeningFunctionalTest {

    @TempDir
    lateinit var projectDir: File

    private val explicitSeed = "aa".repeat(32)

    private fun runner(vararg args: String): GradleRunner =
        GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments(*args, "--stacktrace")
            .forwardOutput()

    private fun writeFixture(registryBlock: String) {
        File(projectDir, "settings.gradle.kts").writeText(
            """
            rootProject.name = "fixture"
            buildCache { local { directory = file("build-cache") } }
            """.trimIndent(),
        )
        File(projectDir, "gradle.properties").writeText("org.gradle.caching=true\n")
        File(projectDir, "build.gradle.kts").writeText(
            """
            plugins { id("io.kseal.android.harden") }

            ksealHarden {
                injectSdk.set(false)
                packageId.set("com.example.fixture")
                versionName.set("1.4.2")
                versionCode.set(142L)
                resourcesDir.set(layout.projectDirectory.dir("res"))
                classesDirs.from(layout.projectDirectory.dir("classes"))
                keepRuleFiles.from(layout.projectDirectory.file("keep.pro"))
                mappingFile.set(layout.projectDirectory.file("mapping.txt"))
                keepStringKeys.add("app_name")
                polymorphism { explicitSeedHex.set("$explicitSeed") }
                $registryBlock
            }
            """.trimIndent(),
        )

        File(projectDir, "res/values").mkdirs()
        File(projectDir, "res/values/strings.xml").writeText(
            """
            <?xml version="1.0" encoding="utf-8"?>
            <resources>
                <string name="app_name">Fixture</string>
                <string name="api_secret">super-secret-value</string>
            </resources>
            """.trimIndent(),
        )

        File(projectDir, "keep.pro").writeText("-keep class com.example.fixture.KeepMe { *; }\n")
        File(projectDir, "mapping.txt").writeText(
            """
            com.example.fixture.App -> a.a.a:
                int counter -> a
            """.trimIndent(),
        )

        val classDir = File(projectDir, "classes/com/example/fixture")
        classDir.mkdirs()
        File(classDir, "Sample.class").writeBytes(sampleClassWithDebugInfo())
    }

    private fun sampleClassWithDebugInfo(): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "com/example/fixture/Sample", null, "java/lang/Object", null)
        cw.visitSource("Sample.kt", null)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null)
        mv.visitCode()
        val l = Label()
        mv.visitLabel(l)
        mv.visitLineNumber(11, l)
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(0, 1)
        mv.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun manifestText(): String {
        val f = File(projectDir, "build/kseal/build-proof/manifest.json")
        assertTrue(f.isFile, "manifest.json must be emitted")
        return f.readText()
    }

    @Test
    fun `offline pipeline emits manifest, seals strings, keeps mapping intact`() {
        writeFixture("registry { offline.set(true) }")
        val result = runner("ksealHarden").build()

        assertEquals(TaskOutcome.SUCCESS, result.task(":ksealBuildProofManifest")?.outcome)
        assertEquals(TaskOutcome.SUCCESS, result.task(":ksealRegisterBuild")?.outcome)

        val doc = manifestText()
        assertTrue(doc.contains("\"schema\": \"kseal.build-proof/v1\""))
        assertTrue(doc.contains("\"platform\": \"android\""))
        assertTrue(doc.contains("\"build_hash\":"))
        assertTrue(doc.contains("\"package_id\": \"com.example.fixture\""))
        assertTrue(doc.contains("\"version_code\": 142"))
        listOf("polymorphism", "strip-debug-metadata", "string-resource-seal").forEach {
            assertTrue(doc.contains("\"$it\""), "manifest must record transform $it")
        }

        // Sealed strings: secret obfuscated, kept name in clear.
        val hardenedStrings = File(projectDir, "build/kseal/hardened/res/values/strings.xml").readText()
        assertTrue(hardenedStrings.contains(">Fixture<"))
        assertFalse(hardenedStrings.contains("super-secret-value"))
        assertTrue(File(projectDir, "build/kseal/hardened/assets/kseal/strings.sealed").isFile)

        // R8 mapping preserved verbatim at the top of the composed mapping.
        val composed = File(projectDir, "build/kseal/hardened/mapping.txt").readText()
        assertTrue(composed.contains("com.example.fixture.App -> a.a.a:"))
        assertTrue(composed.contains("# kseal-build-proof mapping addendum v1"))

        // Offline receipt + uploadable manifest staged.
        val receipt = File(projectDir, "build/kseal/build-proof/registration-receipt.json").readText()
        assertTrue(receipt.contains("\"mode\": \"offline\""))
        assertTrue(File(projectDir, "build/kseal/build-proof/uploadable-manifest.json").isFile)
    }

    @Test
    fun `tasks are up-to-date on unchanged re-run`() {
        writeFixture("registry { offline.set(true) }")
        runner("ksealHarden").build()
        val second = runner("ksealHarden").build()

        listOf(
            ":ksealGeneratePolymorphismSeed",
            ":ksealHardenResources",
            ":ksealStripDebugMetadata",
            ":ksealBuildProofManifest",
            ":ksealRegisterBuild",
        ).forEach { task ->
            assertEquals(TaskOutcome.UP_TO_DATE, second.task(task)?.outcome, "$task should be UP-TO-DATE")
        }
    }

    @Test
    fun `pipeline is configuration-cache compatible`() {
        writeFixture("registry { offline.set(true) }")
        runner("ksealHarden", "--configuration-cache").build()
        val second = runner("ksealHarden", "--configuration-cache").build()
        assertTrue(
            second.output.contains("Configuration cache entry reused"),
            "second run should reuse the configuration cache",
        )
    }

    @Test
    fun `cacheable tasks are restored from the build cache`() {
        writeFixture("registry { offline.set(true) }")
        runner("ksealHarden").build()

        // Wipe outputs but keep the build cache, then rebuild.
        File(projectDir, "build/kseal").deleteRecursively()
        val cached = runner("ksealHarden").build()

        listOf(":ksealHardenResources", ":ksealStripDebugMetadata", ":ksealBuildProofManifest").forEach { task ->
            assertEquals(TaskOutcome.FROM_CACHE, cached.task(task)?.outcome, "$task should be FROM-CACHE")
        }
    }
}
