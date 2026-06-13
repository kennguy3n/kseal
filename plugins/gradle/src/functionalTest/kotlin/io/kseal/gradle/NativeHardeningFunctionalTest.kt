package io.kseal.gradle

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class NativeHardeningFunctionalTest {

    @TempDir
    lateinit var projectDir: File

    private fun runner(vararg args: String): GradleRunner =
        GradleRunner.create()
            .withProjectDir(projectDir)
            .withPluginClasspath()
            .withArguments(*args, "--stacktrace")
            .forwardOutput()

    private fun writeFixture() {
        File(projectDir, "settings.gradle.kts").writeText("rootProject.name = \"native-fixture\"\n")
        File(projectDir, "build.gradle.kts").writeText(
            """
            plugins { id("io.kseal.android.harden") }

            ksealHarden {
                injectSdk.set(false)
                packageId.set("com.example.native")
                versionName.set("2.0.0")
                versionCode.set(200L)
                nativeLibsDirs.from(layout.projectDirectory.dir("jniLibs"))
                polymorphism { explicitSeedHex.set("${"bb".repeat(32)}") }
                registry { offline.set(true) }
            }
            """.trimIndent(),
        )

        // A fully-hardened arm64 library and an x86_64 library where MTE/BTI/PAC cannot apply.
        File(projectDir, "jniLibs/arm64-v8a").mkdirs()
        File(projectDir, "jniLibs/x86_64").mkdirs()
        File(projectDir, "jniLibs/arm64-v8a/libhardened.so")
            .writeBytes(elf(machine = 183, cfi = true, memtagMode = 0b0101 or 0b1000, aarch64Bits = 0b11))
        File(projectDir, "jniLibs/x86_64/libnative.so")
            .writeBytes(elf(machine = 62, cfi = true, memtagMode = null, aarch64Bits = null))
    }

    @Test
    fun `pipeline records native hardening posture and native artifacts`() {
        writeFixture()
        val result = runner("ksealHarden").build()

        assertEquals(TaskOutcome.SUCCESS, result.task(":ksealHardenNativeLibraries")?.outcome)
        assertEquals(TaskOutcome.SUCCESS, result.task(":ksealBuildProofManifest")?.outcome)

        val doc = File(projectDir, "build/kseal/build-proof/manifest.json").readText()
        assertTrue(doc.contains("\"native-library-harden\""), "manifest must record the native transform")
        // The hardened libraries are content-hashed into the artifact set (and thus the build hash).
        assertTrue(doc.contains("native/arm64-v8a/libhardened.so"), "arm64 .so must be a recorded artifact")
        assertTrue(doc.contains("native/x86_64/libnative.so"), "x86_64 .so must be a recorded artifact")

        // arm64: every feature enabled. x86_64: MTE/BTI/PAC unsupported but CFI verified.
        assertTrue(doc.contains("\"aarch64\""))
        assertTrue(doc.contains("\"unsupported\""), "x86_64 MTE/BTI/PAC must be reported as unsupported, not skipped")
        assertTrue(doc.contains("\"cfi_enabled\": 2"), "both libraries should have CFI verified")
        // The aggregate summary must carry the unsupported counts the MASVS report consumes,
        // not just the per-library wire values (the x86_64 slice can't support MTE/BTI/PAC).
        assertTrue(doc.contains("\"mte_unsupported\": 1"), "x86_64 MTE must be tallied as unsupported")
        assertTrue(doc.contains("\"bti_unsupported\": 1"), "x86_64 BTI must be tallied as unsupported")
        assertTrue(doc.contains("\"pac_unsupported\": 1"), "x86_64 PAC must be tallied as unsupported")
        assertTrue(doc.contains("\"cfi_unsupported\": 0"), "both ABIs support CFI, so none are unsupported")

        val report = File(projectDir, "build/kseal/reports/native.json").readText()
        assertTrue(report.contains("\"library_count\": 2"))
        assertTrue(report.contains("\"status\": \"applied\""))
    }

    @Test
    fun `transform is reported as skipped when there are no native libraries`() {
        File(projectDir, "settings.gradle.kts").writeText("rootProject.name = \"empty-native\"\n")
        File(projectDir, "build.gradle.kts").writeText(
            """
            plugins { id("io.kseal.android.harden") }
            ksealHarden {
                injectSdk.set(false)
                packageId.set("com.example.empty")
                polymorphism { explicitSeedHex.set("${"cc".repeat(32)}") }
                registry { offline.set(true) }
            }
            """.trimIndent(),
        )
        runner("ksealHarden").build()

        val doc = File(projectDir, "build/kseal/build-proof/manifest.json").readText()
        assertTrue(doc.contains("\"native-library-harden\""))
        assertTrue(doc.contains("\"status\": \"skipped\""), "no-libraries case must be reported, not silently dropped")
    }

    // --- Minimal 64-bit ELF builder (mirrors the structures ElfInspector keys off) ---

    private fun elf(machine: Int, cfi: Boolean, memtagMode: Int?, aarch64Bits: Int?): ByteArray {
        val order = ByteOrder.LITTLE_ENDIAN
        val dynstr = (if (cfi) "\u0000__cfi_check\u0000" else "\u0000").toByteArray()
        val dynsym = ByteArray((if (cfi) 2 else 1) * 24)
        if (cfi) ByteBuffer.wrap(dynsym).order(order).putInt(24, 1)
        val memtag = memtagMode?.let { note(order, "Android", 4, ByteBuffer.allocate(4).order(order).putInt(it).array()) } ?: ByteArray(0)
        val prop = aarch64Bits?.let {
            val d = ByteBuffer.allocate(16).order(order)
            d.putInt(0xc0000000.toInt()); d.putInt(4); d.putInt(it); d.putInt(0)
            note(order, "GNU", 5, d.array())
        } ?: ByteArray(0)

        val names = listOf("", ".dynsym", ".dynstr", ".note.android.memtag", ".note.gnu.property", ".shstrtab")
        val shstrBytes = StringBuilder().also { sb -> names.forEach { sb.append(it).append('\u0000') } }.toString().toByteArray()
        val nameOffsets = HashMap<String, Int>().also { var o = 0; names.forEach { n -> it[n] = o; o += n.toByteArray().size + 1 } }

        val datas = listOf(ByteArray(0), dynsym, dynstr, memtag, prop, shstrBytes)
        val types = listOf(0, 11, 3, 7, 7, 3)
        val links = listOf(0, 2, 0, 0, 0, 0)
        val entsizes = listOf(0L, 24L, 0L, 0L, 0L, 0L)
        val shnum = names.size
        val shoff = 64L
        var cursor = shoff + shnum * 64L
        val offsets = LongArray(shnum)
        for (i in 0 until shnum) { offsets[i] = if (datas[i].isEmpty()) 0 else cursor; cursor += datas[i].size }

        val buf = ByteBuffer.allocate(cursor.toInt()).order(order)
        buf.put(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
        buf.put(2); buf.put(1); buf.put(1)
        while (buf.position() < 16) buf.put(0)
        buf.putShort(3); buf.putShort(machine.toShort()); buf.putInt(1)
        buf.putLong(0); buf.putLong(0); buf.putLong(shoff); buf.putInt(0)
        buf.putShort(64); buf.putShort(0); buf.putShort(0); buf.putShort(64)
        buf.putShort(shnum.toShort()); buf.putShort((shnum - 1).toShort())
        for (i in 0 until shnum) {
            buf.position((shoff + i * 64L).toInt())
            buf.putInt(nameOffsets.getValue(names[i])); buf.putInt(types[i])
            buf.putLong(0); buf.putLong(0); buf.putLong(offsets[i]); buf.putLong(datas[i].size.toLong())
            buf.putInt(links[i]); buf.putInt(0); buf.putLong(0); buf.putLong(entsizes[i])
        }
        for (i in 0 until shnum) {
            if (datas[i].isEmpty()) continue
            buf.position(offsets[i].toInt()); buf.put(datas[i])
        }
        return buf.array()
    }

    private fun note(order: ByteOrder, name: String, type: Int, desc: ByteArray): ByteArray {
        val nameBytes = (name + "\u0000").toByteArray()
        fun align4(n: Int) = (n + 3) and 3.inv()
        val b = ByteBuffer.allocate(12 + align4(nameBytes.size) + align4(desc.size)).order(order)
        b.putInt(nameBytes.size); b.putInt(desc.size); b.putInt(type)
        b.put(nameBytes); repeat(align4(nameBytes.size) - nameBytes.size) { b.put(0) }
        b.put(desc); repeat(align4(desc.size) - desc.size) { b.put(0) }
        return b.array()
    }
}
