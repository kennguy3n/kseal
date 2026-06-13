package io.kseal.gradle.internal

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class ElfInspectorTest {

    @TempDir
    lateinit var dir: File

    private fun write(name: String, bytes: ByteArray): File =
        File(dir, name).apply { writeBytes(bytes) }

    @Test
    fun `fully hardened aarch64 library reports every feature enabled`() {
        val so = write(
            "libfull.so",
            ElfFixture(
                machine = ElfInspector.Arch.AARCH64.machine,
                cfi = true,
                memtagMode = 0b0101 or 0b1000, // sync + heap + stack
                aarch64Bits = 0b11, // BTI | PAC
            ).build(),
        )
        val r = ElfInspector.inspect(so)

        assertEquals(ElfInspector.Arch.AARCH64, r.arch)
        assertEquals(ElfInspector.Status.ENABLED, r.cfi)
        assertEquals(ElfInspector.Status.ENABLED, r.mte)
        assertEquals(ElfInspector.Status.ENABLED, r.bti)
        assertEquals(ElfInspector.Status.ENABLED, r.pac)
        assertEquals("sync (heap+stack)", r.mteMode)
        assert(r.fullyHardened)
        assert(r.notes.isEmpty()) { "fully hardened library should have no findings: ${r.notes}" }
    }

    @Test
    fun `aarch64 library missing hardening is reported as a finding, not skipped`() {
        val so = write(
            "libbare.so",
            ElfFixture(
                machine = ElfInspector.Arch.AARCH64.machine,
                cfi = false,
                memtagMode = 0, // present but level none => absent
                aarch64Bits = 0,
            ).build(),
        )
        val r = ElfInspector.inspect(so)

        assertEquals(ElfInspector.Status.ABSENT, r.cfi)
        assertEquals(ElfInspector.Status.ABSENT, r.mte)
        assertEquals(ElfInspector.Status.ABSENT, r.bti)
        assertEquals(ElfInspector.Status.ABSENT, r.pac)
        assert(!r.fullyHardened)
        assert(r.notes.size == 4) { "each missing feature must surface a finding: ${r.notes}" }
    }

    @Test
    fun `MTE and branch-protection are unsupported on x86_64, CFI still verified`() {
        val so = write(
            "libx86.so",
            ElfFixture(
                machine = ElfInspector.Arch.X86_64.machine,
                cfi = true,
                memtagMode = null,
                aarch64Bits = null,
            ).build(),
        )
        val r = ElfInspector.inspect(so)

        assertEquals(ElfInspector.Arch.X86_64, r.arch)
        assertEquals(ElfInspector.Status.ENABLED, r.cfi)
        assertEquals(ElfInspector.Status.UNSUPPORTED, r.mte)
        assertEquals(ElfInspector.Status.UNSUPPORTED, r.bti)
        assertEquals(ElfInspector.Status.UNSUPPORTED, r.pac)
        // Unsupported features are reported (not silently skipped) but are not findings.
        assert(r.notes.isEmpty())
    }

    @Test
    fun `32-bit arm library treats MTE as unsupported but CFI as supported`() {
        val so = write(
            "libarm.so",
            ElfFixture(
                machine = ElfInspector.Arch.ARM.machine,
                cfi = false,
                memtagMode = null,
                aarch64Bits = null,
                is64 = false,
            ).build(),
        )
        val r = ElfInspector.inspect(so)

        assertEquals(ElfInspector.Arch.ARM, r.arch)
        assertEquals(ElfInspector.Status.ABSENT, r.cfi)
        assertEquals(ElfInspector.Status.UNSUPPORTED, r.mte)
    }

    @Test
    fun `non-ELF input is indeterminate rather than throwing`() {
        val r = ElfInspector.inspect(write("not.so", "definitely not an elf".toByteArray()))
        assertEquals(ElfInspector.Arch.UNKNOWN, r.arch)
        assertEquals(ElfInspector.Status.INDETERMINATE, r.cfi)
        assertEquals(ElfInspector.Status.INDETERMINATE, r.mte)
    }

    @Test
    fun `parses real system shared objects when present`() {
        // Independent validation against real, toolchain-produced ELF binaries
        // (skips on hosts that don't ship them, so CI stays portable).
        val candidates = mapOf(
            "/usr/aarch64-linux-gnu/lib/libc.so.6" to ElfInspector.Arch.AARCH64,
            "/lib/x86_64-linux-gnu/libc.so.6" to ElfInspector.Arch.X86_64,
            "/usr/lib/x86_64-linux-gnu/libc.so.6" to ElfInspector.Arch.X86_64,
        )
        var checked = 0
        for ((path, expectedArch) in candidates) {
            val f = File(path)
            if (!f.isFile) continue
            checked++
            val r = ElfInspector.inspect(f)
            assertEquals(expectedArch, r.arch, "arch for $path")
            // A real binary must parse: features resolve to a concrete state, never indeterminate.
            assert(r.cfi != ElfInspector.Status.INDETERMINATE) { "$path should parse as ELF" }
            assertEquals(Crypto.sha256Hex(f.readBytes()), r.sha256)
        }
        org.junit.jupiter.api.Assumptions.assumeTrue(checked > 0, "no system shared objects available to validate against")
    }

    @Test
    fun `digest reflects file content`() {
        val so = write("libhash.so", ElfFixture(ElfInspector.Arch.AARCH64.machine, cfi = true).build())
        assertEquals(Crypto.sha256Hex(so.readBytes()), ElfInspector.inspect(so).sha256)
    }

    /**
     * Builds a minimal but structurally valid little-endian ELF with a `.dynsym`
     * (optionally exporting `__cfi_check`), an Android MEMTAG note, and a GNU
     * program-property note — exactly the structures [ElfInspector] keys off.
     */
    private class ElfFixture(
        val machine: Int,
        val cfi: Boolean = false,
        val memtagMode: Int? = null,
        val aarch64Bits: Int? = null,
        val is64: Boolean = true,
    ) {
        fun build(): ByteArray {
            val ehsize = if (is64) 64 else 52
            val shentsize = if (is64) 64 else 40
            val symEnt = if (is64) 24 else 16

            val dynstr = buildString {
                append('\u0000')
                if (cfi) append("__cfi_check\u0000")
            }.toByteArray(Charsets.UTF_8)
            val cfiNameOff = if (cfi) 1 else 0

            // .dynsym: null symbol + (optional) __cfi_check (st_name is the first field in both classes).
            val symCount = if (cfi) 2 else 1
            val dynsym = ByteArray(symCount * symEnt)
            if (cfi) ByteBuffer.wrap(dynsym).order(ORDER).putInt(symEnt, cfiNameOff)

            val memtag = memtagMode?.let { note("Android", NT_MEMTAG, int32(it)) } ?: ByteArray(0)
            val gnuProp = aarch64Bits?.let { note("GNU", NT_GNU_PROP, gnuProperty(it)) } ?: ByteArray(0)

            val names = listOf("", ".dynsym", ".dynstr", ".note.android.memtag", ".note.gnu.property", ".shstrtab")
            val shstr = buildShstrtab(names)

            val datas = listOf(ByteArray(0), dynsym, dynstr, memtag, gnuProp, shstr.bytes)
            val types = listOf(0, SHT_DYNSYM, SHT_STRTAB, SHT_NOTE, SHT_NOTE, SHT_STRTAB)
            val links = listOf(0, 2, 0, 0, 0, 0) // .dynsym links to .dynstr (index 2)
            val entsizes = listOf(0L, symEnt.toLong(), 0L, 0L, 0L, 0L)

            val shnum = names.size
            val shoff = ehsize.toLong()
            val dataStart = shoff + shnum.toLong() * shentsize

            val offsets = LongArray(shnum)
            var cursor = dataStart
            for (i in 0 until shnum) {
                offsets[i] = if (datas[i].isEmpty()) 0 else cursor
                cursor += datas[i].size
            }
            val buf = ByteBuffer.allocate(cursor.toInt()).order(ORDER)

            // ELF header.
            buf.put(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte()))
            buf.put(if (is64) 2 else 1) // EI_CLASS
            buf.put(1) // little-endian
            buf.put(1) // version
            while (buf.position() < 16) buf.put(0)
            buf.putShort(3) // e_type ET_DYN
            buf.putShort(machine.toShort())
            buf.putInt(1) // e_version
            putAddr(buf, 0) // e_entry
            putAddr(buf, 0) // e_phoff
            putAddr(buf, shoff) // e_shoff
            buf.putInt(0) // e_flags
            buf.putShort(ehsize.toShort())
            buf.putShort(0) // e_phentsize
            buf.putShort(0) // e_phnum
            buf.putShort(shentsize.toShort())
            buf.putShort(shnum.toShort())
            buf.putShort((shnum - 1).toShort()) // e_shstrndx => .shstrtab

            // Section header table.
            for (i in 0 until shnum) {
                buf.position((shoff + i * shentsize.toLong()).toInt())
                buf.putInt(shstr.offsetOf(names[i])) // sh_name
                buf.putInt(types[i]) // sh_type
                putAddr(buf, 0) // sh_flags
                putAddr(buf, 0) // sh_addr
                putAddr(buf, offsets[i]) // sh_offset
                putAddr(buf, datas[i].size.toLong()) // sh_size
                buf.putInt(links[i]) // sh_link
                buf.putInt(0) // sh_info
                putAddr(buf, 0) // sh_addralign
                putAddr(buf, entsizes[i]) // sh_entsize
            }

            // Section data.
            for (i in 0 until shnum) {
                if (datas[i].isEmpty()) continue
                buf.position(offsets[i].toInt())
                buf.put(datas[i])
            }
            return buf.array()
        }

        private fun putAddr(buf: ByteBuffer, value: Long) {
            if (is64) buf.putLong(value) else buf.putInt(value.toInt())
        }

        private fun int32(v: Int): ByteArray = ByteBuffer.allocate(4).order(ORDER).putInt(v).array()

        private fun gnuProperty(bits: Int): ByteArray {
            val b = ByteBuffer.allocate(16).order(ORDER)
            b.putInt(GNU_PROPERTY_AARCH64_FEATURE_1_AND)
            b.putInt(4) // data size
            b.putInt(bits)
            b.putInt(0) // pad to 8
            return b.array()
        }

        private fun note(name: String, type: Int, desc: ByteArray): ByteArray {
            val nameBytes = (name + "\u0000").toByteArray(Charsets.UTF_8)
            val namePad = align4(nameBytes.size)
            val descPad = align4(desc.size)
            val b = ByteBuffer.allocate(12 + namePad + descPad).order(ORDER)
            b.putInt(nameBytes.size)
            b.putInt(desc.size)
            b.putInt(type)
            b.put(nameBytes)
            repeat(namePad - nameBytes.size) { b.put(0) }
            b.put(desc)
            repeat(descPad - desc.size) { b.put(0) }
            return b.array()
        }

        private fun buildShstrtab(names: List<String>): Shstrtab {
            val sb = StringBuilder()
            val offsets = HashMap<String, Int>()
            for (n in names) {
                offsets[n] = sb.length
                sb.append(n).append('\u0000')
            }
            return Shstrtab(sb.toString().toByteArray(Charsets.UTF_8), offsets)
        }

        private fun align4(n: Int): Int = (n + 3) and 3.inv()

        private class Shstrtab(val bytes: ByteArray, private val offsets: Map<String, Int>) {
            fun offsetOf(name: String): Int = offsets.getValue(name)
        }

        companion object {
            val ORDER: ByteOrder = ByteOrder.LITTLE_ENDIAN
            const val SHT_STRTAB = 3
            const val SHT_NOTE = 7
            const val SHT_DYNSYM = 11
            const val NT_MEMTAG = 4
            const val NT_GNU_PROP = 5
            const val GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000.toInt()
        }
    }
}
