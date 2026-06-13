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
        // The memtag note exists but its level is none: the diagnostic must say so,
        // not falsely claim the note is missing.
        assert(r.notes.any { it.contains("MTE note present but level is none") }) {
            "level-none MTE must be diagnosed accurately: ${r.notes}"
        }
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

    @Test
    fun `full exploit-mitigation posture is reported as enabled with no findings`() {
        val so = write(
            "libmitigated.so",
            ElfFixture(
                machine = ElfInspector.Arch.AARCH64.machine,
                relro = Relro.FULL,
                execStack = false, // NX: PT_GNU_STACK is non-executable
                pie = true,
                stackCanary = true,
                fortify = true,
            ).build(),
        )
        val r = ElfInspector.inspect(so)

        assertEquals(ElfInspector.Status.ENABLED, r.relro)
        assertEquals("full", r.relroMode)
        assertEquals(ElfInspector.Status.ENABLED, r.nx)
        assertEquals(ElfInspector.Status.ENABLED, r.pie)
        assertEquals(ElfInspector.Status.ENABLED, r.stackCanary)
        assertEquals(ElfInspector.Status.ENABLED, r.fortify)
        assert(r.mitigationsComplete)
        assert(r.postureNotes.isEmpty()) { "fully mitigated library should have no posture findings: ${r.postureNotes}" }
    }

    @Test
    fun `partial RELRO without BIND_NOW is a finding`() {
        val so = write(
            "libpartial.so",
            ElfFixture(machine = ElfInspector.Arch.X86_64.machine, relro = Relro.PARTIAL).build(),
        )
        val r = ElfInspector.inspect(so)
        assertEquals(ElfInspector.Status.ABSENT, r.relro)
        assertEquals("partial", r.relroMode)
        assert(r.postureNotes.any { it.contains("partial RELRO") }) { r.postureNotes.toString() }
    }

    @Test
    fun `missing RELRO segment is reported absent`() {
        val so = write("libnorelro.so", ElfFixture(machine = ElfInspector.Arch.X86_64.machine).build())
        val r = ElfInspector.inspect(so)
        assertEquals(ElfInspector.Status.ABSENT, r.relro)
        assertEquals("none", r.relroMode)
    }

    @Test
    fun `executable stack is a finding while non-exec stack is NX`() {
        val exec = write("libexecstack.so", ElfFixture(machine = ElfInspector.Arch.X86_64.machine, execStack = true).build())
        val nx = write("libnx.so", ElfFixture(machine = ElfInspector.Arch.X86_64.machine, execStack = false).build())

        val execResult = ElfInspector.inspect(exec)
        assertEquals(ElfInspector.Status.ABSENT, execResult.nx)
        assert(execResult.postureNotes.any { it.contains("executable stack") })

        assertEquals(ElfInspector.Status.ENABLED, ElfInspector.inspect(nx).nx)
    }

    @Test
    fun `absent PT_GNU_STACK leaves NX indeterminate rather than asserting`() {
        val so = write("libnostack.so", ElfFixture(machine = ElfInspector.Arch.X86_64.machine).build())
        assertEquals(ElfInspector.Status.INDETERMINATE, ElfInspector.inspect(so).nx)
    }

    @Test
    fun `shared object reports PIE as unsupported but a non-PIE executable is a finding`() {
        val lib = write("libshared.so", ElfFixture(machine = ElfInspector.Arch.X86_64.machine).build())
        assertEquals(ElfInspector.Status.UNSUPPORTED, ElfInspector.inspect(lib).pie)

        val exe = write("nopie.elf", ElfFixture(machine = ElfInspector.Arch.X86_64.machine, eType = 2 /* ET_EXEC */).build())
        val r = ElfInspector.inspect(exe)
        assertEquals(ElfInspector.Status.ABSENT, r.pie)
        assert(r.postureNotes.any { it.contains("non-PIE") })
    }

    @Test
    fun `stack-canary and FORTIFY are detected from exported symbols`() {
        val hardened = write(
            "libchk.so",
            ElfFixture(machine = ElfInspector.Arch.X86_64.machine, stackCanary = true, fortify = true).build(),
        )
        val r = ElfInspector.inspect(hardened)
        assertEquals(ElfInspector.Status.ENABLED, r.stackCanary)
        assertEquals(ElfInspector.Status.ENABLED, r.fortify)

        val bare = ElfInspector.inspect(write("libbarechk.so", ElfFixture(machine = ElfInspector.Arch.X86_64.machine).build()))
        assertEquals(ElfInspector.Status.ABSENT, bare.stackCanary)
        assertEquals(ElfInspector.Status.ABSENT, bare.fortify)
    }

    @Test
    fun `non-ELF input leaves the mitigation posture indeterminate`() {
        val r = ElfInspector.inspect(write("blob.so", "not elf".toByteArray()))
        assertEquals(ElfInspector.Status.INDETERMINATE, r.relro)
        assertEquals(ElfInspector.Status.INDETERMINATE, r.nx)
        assertEquals(ElfInspector.Status.INDETERMINATE, r.pie)
        assertEquals(ElfInspector.Status.INDETERMINATE, r.stackCanary)
        assertEquals(ElfInspector.Status.INDETERMINATE, r.fortify)
    }

    @Test
    fun `real system shared objects expose a concrete mitigation posture`() {
        val candidates = listOf(
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/lib/aarch64-linux-gnu/libc.so.6",
        )
        var checked = 0
        for (path in candidates) {
            val f = File(path)
            if (!f.isFile) continue
            checked++
            val r = ElfInspector.inspect(f)
            // A real libc parses to a concrete posture, never indeterminate.
            assert(r.relro != ElfInspector.Status.INDETERMINATE) { "$path RELRO should resolve" }
            // glibc ships RELRO and a non-executable stack.
            assertEquals(ElfInspector.Status.ENABLED, r.nx, "$path should have NX")
        }
        org.junit.jupiter.api.Assumptions.assumeTrue(checked > 0, "no system shared objects available to validate against")
    }

    /**
     * Builds a minimal but structurally valid little-endian ELF with a `.dynsym`
     * (optionally exporting `__cfi_check`), an Android MEMTAG note, and a GNU
     * program-property note — exactly the structures [ElfInspector] keys off.
     */
    enum class Relro { NONE, PARTIAL, FULL }

    private class ElfFixture(
        val machine: Int,
        val cfi: Boolean = false,
        val memtagMode: Int? = null,
        val aarch64Bits: Int? = null,
        val is64: Boolean = true,
        val relro: Relro = Relro.NONE,
        /** null => no PT_GNU_STACK; false => non-exec stack (NX); true => exec stack. */
        val execStack: Boolean? = null,
        val pie: Boolean = false,
        val eType: Int = 3, // ET_DYN
        val stackCanary: Boolean = false,
        val fortify: Boolean = false,
    ) {
        fun build(): ByteArray {
            val ehsize = if (is64) 64 else 52
            val shentsize = if (is64) 64 else 40
            val phentsize = if (is64) 56 else 32
            val symEnt = if (is64) 24 else 16

            // Build .dynstr with every symbol name we need, recording offsets.
            val symbolNames = buildList {
                if (cfi) add("__cfi_check")
                if (stackCanary) add("__stack_chk_fail")
                if (fortify) add("__memcpy_chk")
            }
            val strOffsets = HashMap<String, Int>()
            val dynstrSb = StringBuilder().append('\u0000')
            for (n in symbolNames) {
                strOffsets[n] = dynstrSb.length
                dynstrSb.append(n).append('\u0000')
            }
            val dynstr = dynstrSb.toString().toByteArray(Charsets.UTF_8)

            // .dynsym: null symbol + one entry per name (only st_name matters here).
            val symCount = 1 + symbolNames.size
            val dynsym = ByteArray(symCount * symEnt)
            val symBuf = ByteBuffer.wrap(dynsym).order(ORDER)
            symbolNames.forEachIndexed { i, n -> symBuf.putInt((i + 1) * symEnt, strOffsets.getValue(n)) }

            val memtag = memtagMode?.let { note("Android", NT_MEMTAG, int32(it)) } ?: ByteArray(0)
            val gnuProp = aarch64Bits?.let { note("GNU", NT_GNU_PROP, gnuProperty(it)) } ?: ByteArray(0)
            val dynamic = buildDynamic()

            val names = listOf(
                "", ".dynsym", ".dynstr", ".note.android.memtag", ".note.gnu.property", ".dynamic", ".shstrtab",
            )
            val shstr = buildShstrtab(names)

            val datas = listOf(ByteArray(0), dynsym, dynstr, memtag, gnuProp, dynamic, shstr.bytes)
            val types = listOf(0, SHT_DYNSYM, SHT_STRTAB, SHT_NOTE, SHT_NOTE, SHT_DYNAMIC, SHT_STRTAB)
            val links = listOf(0, 2, 0, 0, 0, 0, 0) // .dynsym links to .dynstr (index 2)
            val entsizes = listOf(0L, symEnt.toLong(), 0L, 0L, 0L, (if (is64) 16L else 8L), 0L)

            val shnum = names.size
            val shoff = ehsize.toLong()

            // Program headers (optional): PT_GNU_RELRO and/or PT_GNU_STACK.
            val segments = buildList {
                if (relro != Relro.NONE) add(PT_GNU_RELRO to PF_R)
                execStack?.let { add(PT_GNU_STACK to (if (it) (PF_R or PF_W or PF_X) else (PF_R or PF_W))) }
            }
            val phnum = segments.size
            val phoff = if (phnum == 0) 0L else shoff + shnum.toLong() * shentsize
            val dataStart = (if (phnum == 0) shoff + shnum.toLong() * shentsize else phoff + phnum.toLong() * phentsize)

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
            buf.putShort(eType.toShort())
            buf.putShort(machine.toShort())
            buf.putInt(1) // e_version
            putAddr(buf, 0) // e_entry
            putAddr(buf, phoff) // e_phoff
            putAddr(buf, shoff) // e_shoff
            buf.putInt(0) // e_flags
            buf.putShort(ehsize.toShort())
            buf.putShort(phentsize.toShort())
            buf.putShort(phnum.toShort())
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

            // Program header table.
            for (i in 0 until phnum) {
                val (type, flags) = segments[i]
                buf.position((phoff + i * phentsize.toLong()).toInt())
                if (is64) {
                    buf.putInt(type) // p_type
                    buf.putInt(flags) // p_flags
                    repeat(6) { putAddr(buf, 0) } // p_offset..p_align
                } else {
                    buf.putInt(type) // p_type
                    putAddr(buf, 0) // p_offset
                    putAddr(buf, 0) // p_vaddr
                    putAddr(buf, 0) // p_paddr
                    putAddr(buf, 0) // p_filesz
                    putAddr(buf, 0) // p_memsz
                    buf.putInt(flags) // p_flags
                    putAddr(buf, 0) // p_align
                }
            }

            // Section data.
            for (i in 0 until shnum) {
                if (datas[i].isEmpty()) continue
                buf.position(offsets[i].toInt())
                buf.put(datas[i])
            }
            return buf.array()
        }

        /** Builds a `.dynamic` table carrying DT_FLAGS_1 (DF_1_NOW / DF_1_PIE) + DT_NULL. */
        private fun buildDynamic(): ByteArray {
            var flags1 = 0L
            if (relro == Relro.FULL) flags1 = flags1 or 0x1L // DF_1_NOW
            if (pie) flags1 = flags1 or 0x08000000L // DF_1_PIE
            if (flags1 == 0L) return ByteArray(0)
            val entSize = if (is64) 16 else 8
            val buf = ByteBuffer.allocate(entSize * 2).order(ORDER)
            putAddr(buf, 0x6ffffffbL) // DT_FLAGS_1
            putAddr(buf, flags1)
            putAddr(buf, 0L) // DT_NULL
            putAddr(buf, 0L)
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
            const val SHT_DYNAMIC = 6
            const val SHT_NOTE = 7
            const val SHT_DYNSYM = 11
            const val NT_MEMTAG = 4
            const val NT_GNU_PROP = 5
            const val PT_GNU_STACK = 0x6474e551
            const val PT_GNU_RELRO = 0x6474e552
            const val PF_X = 1
            const val PF_W = 2
            const val PF_R = 4
            const val GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000.toInt()
        }
    }
}
