package io.kseal.gradle.internal

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * A small, dependency-free ELF reader that detects the native-hardening posture
 * of a shared object (`.so`) at build time.
 *
 * CFI (Control-Flow Integrity) and MTE (Memory-Tagging Extension), together with
 * the AArch64 branch-protection features BTI/PAC, are *compile/link*-time
 * properties of the toolchain — a Gradle plugin operating on already-linked
 * `.so` files cannot inject them after the fact. What it can (and must) do is
 * **verify** them on every shipped library and record the result in the
 * build-proof manifest, so the control plane has cryptographic evidence of which
 * targets are hardened and which are not. Where a feature simply cannot apply to
 * a target (e.g. MTE on a 32-bit or x86 ABI) we report it as `unsupported`
 * rather than silently dropping it.
 *
 * Detection is purely structural (ELF section/symbol/note parsing) so it needs
 * no NDK on the build host and is fully deterministic and unit-testable. The
 * parser is defensive: any malformed/oversized field yields an `unknown`
 * architecture and `indeterminate` features rather than throwing, so a single
 * odd library never breaks a build.
 */
internal object ElfInspector {

    /** Per-feature verification outcome recorded in the manifest. */
    enum class Status(val wire: String) {
        /** The hardening marker is present in the binary. */
        ENABLED("enabled"),

        /** Supported on this target but the marker is absent — a real finding. */
        ABSENT("absent"),

        /** Cannot apply to this target (wrong ABI / not an aarch64 feature). */
        UNSUPPORTED("unsupported"),

        /** The file could not be parsed as ELF; nothing can be asserted. */
        INDETERMINATE("indeterminate"),
    }

    /** CPU architecture, derived from the ELF `e_machine` field. */
    enum class Arch(val machine: Int, val id: String) {
        AARCH64(183, "aarch64"),
        ARM(40, "arm"),
        X86_64(62, "x86_64"),
        X86(3, "x86"),
        RISCV(243, "riscv64"),
        UNKNOWN(-1, "unknown");

        /** AArch64 is the only Android ABI that supports MTE and BTI/PAC. */
        val isAarch64: Boolean get() = this == AARCH64

        /** LLVM CFI is available on all the production Android ABIs we ship. */
        val supportsCfi: Boolean get() = this != UNKNOWN

        companion object {
            fun from(machine: Int): Arch = values().firstOrNull { it.machine == machine } ?: UNKNOWN
        }
    }

    /** The hardening posture of a single `.so`. */
    data class Result(
        val arch: Arch,
        val sha256: String,
        val cfi: Status,
        val mte: Status,
        val bti: Status,
        val pac: Status,
        val mteMode: String?,
        val notes: List<String>,
    ) {
        /** True when every feature applicable to this target is enabled. */
        val fullyHardened: Boolean
            get() = listOf(cfi, mte, bti, pac).none { it == Status.ABSENT || it == Status.INDETERMINATE }
    }

    private const val EI_NIDENT = 16
    private val ELF_MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())

    // Section header types.
    private const val SHT_SYMTAB = 2
    private const val SHT_NOTE = 7
    private const val SHT_DYNSYM = 11

    // Note types.
    private const val NT_GNU_PROPERTY_TYPE_0 = 5
    private const val NT_ANDROID_TYPE_MEMTAG = 4

    // GNU program-property tags / bits (AArch64 branch protection).
    private const val GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000.toInt()
    private const val GNU_PROPERTY_AARCH64_FEATURE_1_BTI = 1
    private const val GNU_PROPERTY_AARCH64_FEATURE_1_PAC = 2

    // Android MEMTAG descriptor bits (see Android's <android/note.h>).
    private const val NT_MEMTAG_LEVEL_MASK = 3
    private const val NT_MEMTAG_HEAP = 4
    private const val NT_MEMTAG_STACK = 8

    fun inspect(file: File): Result {
        val bytes = file.readBytes()
        val sha = Crypto.sha256Hex(bytes)
        val parsed = runCatching { parse(bytes) }.getOrNull()
            ?: return Result(
                arch = Arch.UNKNOWN,
                sha256 = sha,
                cfi = Status.INDETERMINATE,
                mte = Status.INDETERMINATE,
                bti = Status.INDETERMINATE,
                pac = Status.INDETERMINATE,
                mteMode = null,
                notes = listOf("not a parseable ELF object"),
            )

        val notes = mutableListOf<String>()
        val arch = parsed.arch

        val cfi = when {
            !arch.supportsCfi -> Status.UNSUPPORTED
            parsed.hasCfiSymbol -> Status.ENABLED
            else -> Status.ABSENT.also { notes += "no __cfi_check symbol; build with -fsanitize=cfi" }
        }
        val mte = when {
            !arch.isAarch64 -> Status.UNSUPPORTED
            parsed.memtag != null && (parsed.memtag and NT_MEMTAG_LEVEL_MASK) != 0 -> Status.ENABLED
            parsed.memtag != null -> Status.ABSENT.also { notes += "MTE note present but level is none; link with -fsanitize=memtag and set android:memtagMode" }
            else -> Status.ABSENT.also { notes += "no MTE note; link with -fsanitize=memtag and set android:memtagMode" }
        }
        val bti = aarch64Feature(arch, parsed.aarch64Features, GNU_PROPERTY_AARCH64_FEATURE_1_BTI, "BTI", "-mbranch-protection=bti", notes)
        val pac = aarch64Feature(arch, parsed.aarch64Features, GNU_PROPERTY_AARCH64_FEATURE_1_PAC, "PAC", "-mbranch-protection=pac-ret", notes)

        return Result(
            arch = arch,
            sha256 = sha,
            cfi = cfi,
            mte = mte,
            bti = bti,
            pac = pac,
            mteMode = parsed.memtag?.let { memtagMode(it) },
            notes = notes,
        )
    }

    private fun aarch64Feature(arch: Arch, features: Int?, bit: Int, name: String, flag: String, notes: MutableList<String>): Status =
        when {
            !arch.isAarch64 -> Status.UNSUPPORTED
            features != null && (features and bit) != 0 -> Status.ENABLED
            else -> Status.ABSENT.also { notes += "no $name property; build with $flag" }
        }

    private fun memtagMode(descriptor: Int): String = when (descriptor and NT_MEMTAG_LEVEL_MASK) {
        0 -> "none"
        1 -> "sync"
        2 -> "async"
        else -> "reserved"
    }.let { level ->
        val targets = buildList {
            if ((descriptor and NT_MEMTAG_HEAP) != 0) add("heap")
            if ((descriptor and NT_MEMTAG_STACK) != 0) add("stack")
        }
        if (targets.isEmpty()) level else "$level (${targets.joinToString("+")})"
    }

    private class Parsed(
        val arch: Arch,
        val hasCfiSymbol: Boolean,
        val memtag: Int?,
        val aarch64Features: Int?,
    )

    private fun parse(bytes: ByteArray): Parsed {
        require(bytes.size >= EI_NIDENT + 48) { "truncated ELF header" }
        require(bytes.copyOfRange(0, 4).contentEquals(ELF_MAGIC)) { "bad ELF magic" }

        val is64 = when (bytes[4].toInt()) {
            1 -> false
            2 -> true
            else -> error("unknown ELF class")
        }
        val order = when (bytes[5].toInt()) {
            1 -> ByteOrder.LITTLE_ENDIAN
            2 -> ByteOrder.BIG_ENDIAN
            else -> error("unknown ELF endianness")
        }
        val buf = ByteBuffer.wrap(bytes).order(order)

        val machine = buf.getShort(18).toInt() and 0xffff
        val arch = Arch.from(machine)

        // Section header table location and dimensions differ by ELF class.
        val shoff: Long
        val shentsize: Int
        val shnum: Int
        val shstrndx: Int
        if (is64) {
            shoff = buf.getLong(40)
            shentsize = buf.getShort(58).toInt() and 0xffff
            shnum = buf.getShort(60).toInt() and 0xffff
            shstrndx = buf.getShort(62).toInt() and 0xffff
        } else {
            shoff = (buf.getInt(32).toLong() and 0xffffffffL)
            shentsize = buf.getShort(46).toInt() and 0xffff
            shnum = buf.getShort(48).toInt() and 0xffff
            shstrndx = buf.getShort(50).toInt() and 0xffff
        }
        if (shoff == 0L || shnum == 0) {
            return Parsed(arch, hasCfiSymbol = false, memtag = null, aarch64Features = null)
        }

        val sections = (0 until shnum).map { idx ->
            readSection(buf, bytes.size, shoff + idx.toLong() * shentsize, is64)
        }
        val shstr = sections.getOrNull(shstrndx)
        fun nameOf(s: Section): String = shstr?.let { readCString(bytes, it.offset + s.nameOffset) } ?: ""

        var hasCfi = false
        var memtag: Int? = null
        var features: Int? = null

        for (s in sections) {
            when (s.type) {
                SHT_DYNSYM, SHT_SYMTAB -> {
                    val strtab = sections.getOrNull(s.link)
                    if (strtab != null && hasSymbol(bytes, buf, s, strtab, is64, "__cfi_check")) hasCfi = true
                }
                SHT_NOTE -> {
                    parseNotes(bytes, buf, s) { name, type, descOff, descSz ->
                        if (name == "Android" && type == NT_ANDROID_TYPE_MEMTAG && descSz >= 4) {
                            memtag = buf.getInt(descOff)
                        } else if (name == "GNU" && type == NT_GNU_PROPERTY_TYPE_0) {
                            features = parseGnuProperty(buf, descOff, descSz, is64) ?: features
                        }
                    }
                }
            }
        }
        return Parsed(arch, hasCfi, memtag, features)
    }

    private class Section(
        val nameOffset: Int,
        val type: Int,
        val offset: Int,
        val size: Int,
        val link: Int,
        val entSize: Int,
    )

    private fun readSection(buf: ByteBuffer, fileSize: Int, at: Long, is64: Boolean): Section {
        val base = at.toInt()
        return if (is64) {
            Section(
                nameOffset = buf.getInt(base),
                type = buf.getInt(base + 4),
                offset = clampOffset(buf.getLong(base + 24), fileSize),
                size = buf.getLong(base + 32).toInt(),
                link = buf.getInt(base + 40),
                entSize = buf.getLong(base + 56).toInt(),
            )
        } else {
            Section(
                nameOffset = buf.getInt(base),
                type = buf.getInt(base + 4),
                offset = clampOffset(buf.getInt(base + 16).toLong() and 0xffffffffL, fileSize),
                size = buf.getInt(base + 20),
                link = buf.getInt(base + 24),
                entSize = buf.getInt(base + 36),
            )
        }
    }

    private fun clampOffset(value: Long, fileSize: Int): Int =
        if (value in 0..fileSize.toLong()) value.toInt() else fileSize

    private fun hasSymbol(
        bytes: ByteArray,
        buf: ByteBuffer,
        sym: Section,
        strtab: Section,
        is64: Boolean,
        wanted: String,
    ): Boolean {
        val entSize = if (sym.entSize > 0) sym.entSize else if (is64) 24 else 16
        if (entSize <= 0) return false
        val count = sym.size / entSize
        for (i in 0 until count) {
            val entry = sym.offset + i * entSize
            if (entry + 4 > bytes.size) break
            val nameOff = buf.getInt(entry)
            if (nameOff == 0) continue
            if (readCString(bytes, strtab.offset + nameOff) == wanted) return true
        }
        return false
    }

    /** Iterates the note entries of a `SHT_NOTE` section. */
    private inline fun parseNotes(
        bytes: ByteArray,
        buf: ByteBuffer,
        section: Section,
        onNote: (name: String, type: Int, descOffset: Int, descSize: Int) -> Unit,
    ) {
        var p = section.offset
        val end = minOf(section.offset + section.size, bytes.size)
        while (p + 12 <= end) {
            val nameSz = buf.getInt(p)
            val descSz = buf.getInt(p + 4)
            val type = buf.getInt(p + 8)
            if (nameSz < 0 || descSz < 0 || nameSz > end) break
            val nameStart = p + 12
            val name = if (nameSz == 0) "" else readCString(bytes, nameStart)
            val descStart = nameStart + align4(nameSz)
            if (descStart + descSz > end) break
            onNote(name, type, descStart, descSz)
            p = descStart + align4(descSz)
        }
    }

    /**
     * Walks the GNU program-property descriptor for the AArch64 feature mask. The
     * descriptor is a sequence of `(type, size, data[, pad])` records.
     */
    private fun parseGnuProperty(buf: ByteBuffer, descOffset: Int, descSize: Int, is64: Boolean): Int? {
        var p = descOffset
        val end = descOffset + descSize
        while (p + 8 <= end) {
            val type = buf.getInt(p)
            val size = buf.getInt(p + 4)
            val dataStart = p + 8
            if (size < 0 || dataStart + size > end) break
            if (type == GNU_PROPERTY_AARCH64_FEATURE_1_AND && size >= 4) {
                return buf.getInt(dataStart)
            }
            // Program-property records are padded to the pointer size.
            val pad = if (is64) align8(size) else align4(size)
            p = dataStart + pad
        }
        return null
    }

    private fun readCString(bytes: ByteArray, start: Int): String {
        if (start < 0 || start >= bytes.size) return ""
        var i = start
        while (i < bytes.size && bytes[i].toInt() != 0) i++
        return String(bytes, start, i - start, Charsets.UTF_8)
    }

    private fun align4(n: Int): Int = (n + 3) and 3.inv()
    private fun align8(n: Int): Int = (n + 7) and 7.inv()
}
