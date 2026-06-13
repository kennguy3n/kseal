package io.kseal.gradle

import java.io.File
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

/**
 * End-to-end coverage for the bytecode control-flow obfuscation task wired into
 * the pipeline: applied output, mapping-addendum integration, manifest recording,
 * default-off behaviour and per-build polymorphism.
 */
class ObfuscationFunctionalTest {

    @TempDir
    lateinit var projectDir: File

    private fun runner(vararg args: String): GradleRunner =
        GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments(*args, "--stacktrace")
            .forwardOutput()

    private fun writeFixture(obfuscationBlock: String, seedHex: String = "ab".repeat(32)) {
        File(projectDir, "settings.gradle.kts").writeText("rootProject.name = \"obf-fixture\"\n")
        File(projectDir, "build.gradle.kts").writeText(
            """
            plugins { id("io.kseal.android.harden") }
            ksealHarden {
                injectSdk.set(false)
                packageId.set("com.example.obf")
                classesDirs.from(layout.projectDirectory.dir("classes"))
                polymorphism { explicitSeedHex.set("$seedHex") }
                registry { offline.set(true) }
                $obfuscationBlock
            }
            """.trimIndent(),
        )
        val classDir = File(projectDir, "classes/com/example/obf")
        classDir.mkdirs()
        File(classDir, "Sample.class").writeBytes(sampleClass())
    }

    private fun sampleClass(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "com/example/obf/Sample", null, "java/lang/Object", null)
        cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode(); visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN); visitMaxs(0, 0); visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "token", "()Ljava/lang/String;", null, null).apply {
            visitCode(); visitLdcInsn("super-secret-endpoint-token"); visitInsn(Opcodes.ARETURN); visitMaxs(0, 0); visitEnd()
        }
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun manifest() = File(projectDir, "build/kseal/build-proof/manifest.json").readText()

    @Test
    fun `enabled high obfuscation rewrites strings, inserts predicates and records it in the mapping`() {
        writeFixture("obfuscation { enabled.set(true); strength.set(\"high\") }")
        val result = runner("ksealHarden").build()
        assertEquals(TaskOutcome.SUCCESS, result.task(":ksealObfuscateBytecode")?.outcome)

        val report = File(projectDir, "build/kseal/reports/obfuscation.json").readText()
        assertTrue(report.contains("\"status\": \"applied\""))
        assertTrue(report.contains("\"strength\": \"high\""))
        assertTrue(report.contains("\"decoder_class\": \"io/kseal/generated/KsealStrings\""))

        // The decoder class is generated alongside the obfuscated app class.
        assertTrue(File(projectDir, "build/kseal/hardened/obfuscated-classes/io/kseal/generated/KsealStrings.class").isFile)
        val obfClass = File(projectDir, "build/kseal/hardened/obfuscated-classes/com/example/obf/Sample.class").readBytes()
        assertFalse(
            String(obfClass, Charsets.ISO_8859_1).contains("super-secret-endpoint-token"),
            "plaintext must not survive in the obfuscated class",
        )

        // Mapping addendum records the obfuscation, but keeps R8-style content as comments.
        val mapping = File(projectDir, "build/kseal/hardened/mapping.txt").readText()
        assertTrue(mapping.contains("# bytecode-obfuscation: strength=high"))
        assertTrue(mapping.contains("# bytecode-string-decoder: io/kseal/generated/KsealStrings"))

        // Manifest records the transform with applied status.
        val doc = manifest()
        assertTrue(doc.contains("\"bytecode-control-flow-obfuscation\""))
        assertTrue(doc.contains("\"opaque_predicates_inserted\":"))
    }

    @Test
    fun `obfuscation is off by default and passes classes through unchanged`() {
        writeFixture("")
        runner("ksealHarden").build()

        val report = File(projectDir, "build/kseal/reports/obfuscation.json").readText()
        assertTrue(report.contains("\"status\": \"disabled\""))

        // Default mapping carries no obfuscation lines (byte-identical to pre-feature output).
        val mapping = File(projectDir, "build/kseal/hardened/mapping.txt").readText()
        assertFalse(mapping.contains("bytecode-obfuscation"))

        // Pass-through: the obfuscated class equals the stripped class byte-for-byte.
        val stripped = File(projectDir, "build/kseal/hardened/classes/com/example/obf/Sample.class").readBytes()
        val passed = File(projectDir, "build/kseal/hardened/obfuscated-classes/com/example/obf/Sample.class").readBytes()
        assertTrue(stripped.contentEquals(passed))
    }

    @Test
    fun `different seeds produce different build hashes (per-build polymorphism)`() {
        writeFixture("obfuscation { enabled.set(true); strength.set(\"high\") }", seedHex = "11".repeat(32))
        runner("ksealHarden").build()
        val hashA = File(projectDir, "build/kseal/build-proof/build-hash.txt").readText().trim()
        val classA = File(projectDir, "build/kseal/hardened/obfuscated-classes/com/example/obf/Sample.class").readBytes()

        // Rebuild with a different seed.
        File(projectDir, "build.gradle.kts").writeText(
            File(projectDir, "build.gradle.kts").readText().replace("11".repeat(32), "22".repeat(32)),
        )
        File(projectDir, "build/kseal").deleteRecursively()
        runner("ksealHarden").build()
        val hashB = File(projectDir, "build/kseal/build-proof/build-hash.txt").readText().trim()
        val classB = File(projectDir, "build/kseal/hardened/obfuscated-classes/com/example/obf/Sample.class").readBytes()

        assertNotEquals(hashA, hashB, "a new seed must change the build hash")
        assertFalse(classA.contentEquals(classB), "a new seed must change the obfuscated bytecode")
    }
}
