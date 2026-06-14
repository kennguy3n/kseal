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
 * Beyond the memory-safety features the inspector also reports the classic
 * exploit-mitigation posture every shipped ELF should carry — **RELRO**,
 * **NX** (non-executable stack), **PIE**, **stack-canary** and **FORTIFY** —
 * derived from the program headers, the dynamic section and the symbol tables.
 * These are tracked as a separate posture group from the memory-safety findings
 * so each can be evaluated and reported independently.
 *
 * Detection is purely structural (ELF header / program-header / section /
 * symbol / note / dynamic parsing) so it needs no NDK on the build host and is
 * fully deterministic and unit-testable. The parser is defensive: any
 * malformed/oversized field yields an `unknown` architecture and
 * `indeterminate` features rather than throwing, so a single odd library never
 * breaks a build.
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
        // Memory-safety features (toolchain-injected at compile/link time).
        val cfi: Status,
        val mte: Status,
        val bti: Status,
        val pac: Status,
        val mteMode: String?,
        val notes: List<String>,
        // Classic exploit-mitigation posture (RELRO/NX/PIE/canary/FORTIFY).
        val relro: Status = Status.INDETERMINATE,
        val relroMode: String? = null,
        val nx: Status = Status.INDETERMINATE,
        val pie: Status = Status.INDETERMINATE,
        val stackCanary: Status = Status.INDETERMINATE,
        val fortify: Status = Status.INDETERMINATE,
        val postureNotes: List<String> = emptyList(),
    ) {
        /** True when every memory-safety feature applicable to this target is enabled. */
        val fullyHardened: Boolean
            get() = listOf(cfi, mte, bti, pac).none { it == Status.ABSENT || it == Status.INDETERMINATE }

        /**
         * True when every applicable exploit-mitigation feature is enabled.
         * `UNSUPPORTED`/`INDETERMINATE` do not count against the posture (they
         * are reported but cannot be asserted as findings).
         */
        val mitigationsComplete: Boolean
            get() = listOf(relro, nx, pie, stackCanary, fortify).none { it == Status.ABSENT }
    }

    private const val EI_NIDENT = 16
    private val ELF_MAGIC = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())

    // ELF file types.
    private const val ET_EXEC = 2
    private const val ET_DYN = 3

    // Section header types.
    private const val SHT_SYMTAB = 2
    private const val SHT_DYNAMIC = 6
    private const val SHT_NOTE = 7
    private const val SHT_DYNSYM = 11

    // Program header types.
    private const val PT_GNU_STACK = 0x6474e551
    private const val PT_GNU_RELRO = 0x6474e552
    private const val PF_X = 1

    // Dynamic-section tags / flags.
    private const val DT_NULL = 0L
    private const val DT_BIND_NOW = 24L
    private const val DT_FLAGS = 30L
    private const val DT_FLAGS_1 = 0x6ffffffbL
    private const val DF_BIND_NOW = 0x8L
    private const val DF_1_NOW = 0x1L
    private const val DF_1_PIE = 0x08000000L

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
                relro = Status.INDETERMINATE,
                nx = Status.INDETERMINATE,
                pie = Status.INDETERMINATE,
                stackCanary = Status.INDETERMINATE,
                fortify = Status.INDETERMINATE,
                postureNotes = listOf("not a parseable ELF object"),
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

        val postureNotes = mutableListOf<String>()
        val relro = relroStatus(parsed, postureNotes)
        val nx = nxStatus(parsed, postureNotes)
        val pie = pieStatus(parsed, postureNotes)
        val stackCanary = when {
            parsed.hasStackCanary -> Status.ENABLED
            else -> Status.ABSENT.also { postureNotes += "no stack-canary symbol; build with -fstack-protector-strong" }
        }
        val fortify = when {
            parsed.hasFortify -> Status.ENABLED
            else -> Status.ABSENT.also { postureNotes += "no _chk fortified symbols; build with -D_FORTIFY_SOURCE=2" }
        }

        return Result(
            arch = arch,
            sha256 = sha,
            cfi = cfi,
            mte = mte,
            bti = bti,
            pac = pac,
            mteMode = parsed.memtag?.let { memtagMode(it) },
            notes = notes,
            relro = relro,
            relroMode = parsed.relroMode(),
            nx = nx,
            pie = pie,
            stackCanary = stackCanary,
            fortify = fortify,
            postureNotes = postureNotes,
        )
    }

    private fun relroStatus(parsed: Parsed, notes: MutableList<String>): Status = when {
        parsed.hasRelroSegment && parsed.bindNow -> Status.ENABLED
        parsed.hasRelroSegment -> Status.ABSENT.also { notes += "partial RELRO only; link with -Wl,-z,relro,-z,now for full RELRO" }
        else -> Status.ABSENT.also { notes += "no RELRO segment; link with -Wl,-z,relro,-z,now" }
    }

    private fun nxStatus(parsed: Parsed, notes: MutableList<String>): Status = when (parsed.gnuStackExecutable) {
        false -> Status.ENABLED
        true -> Status.ABSENT.also { notes += "executable stack (PT_GNU_STACK is RWX); link with -Wl,-z,noexecstack" }
        // No PT_GNU_STACK: the loader's default differs by platform; we cannot assert.
        null -> Status.INDETERMINATE
    }

    private fun pieStatus(parsed: Parsed, notes: MutableList<String>): Status = when {
        parsed.isPie -> Status.ENABLED
        parsed.eType == ET_EXEC -> Status.ABSENT.also { notes += "non-PIE executable; build with -fPIE -pie" }
        // A shared object (ET_DYN without DF_1_PIE) is inherently position-independent.
        else -> Status.UNSUPPORTED
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
        val eType: Int,
        val hasCfiSymbol: Boolean,
        val memtag: Int?,
        val aarch64Features: Int?,
        val hasRelroSegment: Boolean,
        /** True when PT_GNU_STACK is present and executable; false when present and non-exec; null when absent. */
        val gnuStackExecutable: Boolean?,
        val bindNow: Boolean,
        val dfFlags1: Long,
        val hasStackCanary: Boolean,
        val hasFortify: Boolean,
    ) {
        val isPie: Boolean get() = (dfFlags1 and DF_1_PIE) != 0L

        fun relroMode(): String = when {
            hasRelroSegment && bindNow -> "full"
            hasRelroSegment -> "partial"
            else -> "none"
        }
    }

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

        val eType = buf.getShort(16).toInt() and 0xffff
        val machine = buf.getShort(18).toInt() and 0xffff
        val arch = Arch.from(machine)

        // Program header and section header table locations differ by ELF class.
        val phoff: Long
        val phentsize: Int
        val phnum: Int
        val shoff: Long
        val shentsize: Int
        val shnum: Int
        // Sections are matched by their `sh_type` (DYNSYM/SYMTAB/NOTE/…), not by
        // name, so the section-header string table index (e_shstrndx) is not read.
        if (is64) {
            phoff = buf.getLong(32)
            shoff = buf.getLong(40)
            phentsize = buf.getShort(54).toInt() and 0xffff
            phnum = buf.getShort(56).toInt() and 0xffff
            shentsize = buf.getShort(58).toInt() and 0xffff
            shnum = buf.getShort(60).toInt() and 0xffff
        } else {
            phoff = buf.getInt(28).toLong() and 0xffffffffL
            shoff = buf.getInt(32).toLong() and 0xffffffffL
            phentsize = buf.getShort(42).toInt() and 0xffff
            phnum = buf.getShort(44).toInt() and 0xffff
            shentsize = buf.getShort(46).toInt() and 0xffff
            shnum = buf.getShort(48).toInt() and 0xffff
        }

        val segments = readProgramHeaders(buf, bytes.size, phoff, phentsize, phnum, is64)
        val hasRelroSegment = segments.any { it.type == PT_GNU_RELRO }
        val gnuStackExecutable = segments.firstOrNull { it.type == PT_GNU_STACK }?.let { (it.flags and PF_X) != 0 }

        if (shoff == 0L || shnum == 0) {
            return Parsed(
                arch = arch, eType = eType, hasCfiSymbol = false, memtag = null, aarch64Features = null,
                hasRelroSegment = hasRelroSegment, gnuStackExecutable = gnuStackExecutable,
                bindNow = false, dfFlags1 = 0L, hasStackCanary = false, hasFortify = false,
            )
        }

        val sections = (0 until shnum).map { idx ->
            readSection(buf, bytes.size, shoff + idx.toLong() * shentsize, is64)
        }

        var hasCfi = false
        var memtag: Int? = null
        var features: Int? = null
        var hasCanary = false
        var hasFortify = false

        for (s in sections) {
            when (s.type) {
                SHT_DYNSYM, SHT_SYMTAB -> {
                    val strtab = sections.getOrNull(s.link)
                    if (strtab != null) {
                        forEachSymbolName(bytes, buf, s, strtab, is64) { name ->
                            when {
                                name == "__cfi_check" -> hasCfi = true
                                name == "__stack_chk_fail" || name == "__stack_chk_guard" -> hasCanary = true
                                isFortifiedSymbol(name) -> hasFortify = true
                            }
                        }
                    }
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

        // The dynamic flags (BIND_NOW / DF_1_*) live in the SHT_DYNAMIC section
        // when present, else in the PT_DYNAMIC segment's file range.
        val dynamicSection = sections.firstOrNull { it.type == SHT_DYNAMIC }
        val (bindNow, dfFlags1) = parseDynamic(buf, bytes.size, dynamicSection, is64)

        return Parsed(
            arch = arch,
            eType = eType,
            hasCfiSymbol = hasCfi,
            memtag = memtag,
            aarch64Features = features,
            hasRelroSegment = hasRelroSegment,
            gnuStackExecutable = gnuStackExecutable,
            bindNow = bindNow,
            dfFlags1 = dfFlags1,
            hasStackCanary = hasCanary,
            hasFortify = hasFortify,
        )
    }

    /** Symbols glibc/bionic export for fortified libc wrappers, e.g. `__memcpy_chk`. */
    private fun isFortifiedSymbol(name: String): Boolean =
        name.length > 5 && name.startsWith("__") && name.endsWith("_chk")

    private class Segment(val type: Int, val flags: Int)

    private fun readProgramHeaders(buf: ByteBuffer, fileSize: Int, phoff: Long, phentsize: Int, phnum: Int, is64: Boolean): List<Segment> {
        if (phoff <= 0L || phnum <= 0) return emptyList()
        val entSize = if (phentsize > 0) phentsize else if (is64) 56 else 32
        val out = ArrayList<Segment>(phnum)
        for (i in 0 until phnum) {
            val base = (phoff + i.toLong() * entSize)
            if (base < 0 || base + entSize > fileSize) break
            val at = base.toInt()
            // p_type is the first word in both classes; p_flags moves between them.
            val type = buf.getInt(at)
            val flags = if (is64) buf.getInt(at + 4) else buf.getInt(at + 24)
            out += Segment(type, flags)
        }
        return out
    }

    /** Returns (bindNow, dfFlags1) read from the dynamic section, defaulting to (false, 0). */
    private fun parseDynamic(buf: ByteBuffer, fileSize: Int, dynamic: Section?, is64: Boolean): Pair<Boolean, Long> {
        if (dynamic == null || dynamic.size <= 0) return false to 0L
        val entSize = if (is64) 16 else 8
        val count = dynamic.size / entSize
        var bindNow = false
        var flags1 = 0L
        for (i in 0 until count) {
            val at = dynamic.offset + i * entSize
            if (at < 0 || at + entSize > fileSize) break
            val tag: Long
            val value: Long
            if (is64) {
                tag = buf.getLong(at)
                value = buf.getLong(at + 8)
            } else {
                tag = buf.getInt(at).toLong() and 0xffffffffL
                value = buf.getInt(at + 4).toLong() and 0xffffffffL
            }
            when (tag) {
                DT_NULL -> break
                DT_BIND_NOW -> bindNow = true
                DT_FLAGS -> if ((value and DF_BIND_NOW) != 0L) bindNow = true
                DT_FLAGS_1 -> {
                    flags1 = flags1 or value
                    if ((value and DF_1_NOW) != 0L) bindNow = true
                }
            }
        }
        return bindNow to flags1
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

    /** Invokes [onName] for every named symbol in [sym]'s table. */
    private inline fun forEachSymbolName(
        bytes: ByteArray,
        buf: ByteBuffer,
        sym: Section,
        strtab: Section,
        is64: Boolean,
        onName: (String) -> Unit,
    ) {
        val entSize = if (sym.entSize > 0) sym.entSize else if (is64) 24 else 16
        if (entSize <= 0) return
        val count = sym.size / entSize
        for (i in 0 until count) {
            val entry = sym.offset + i * entSize
            if (entry + 4 > bytes.size) break
            val nameOff = buf.getInt(entry)
            if (nameOff == 0) continue
            onName(readCString(bytes, strtab.offset + nameOff))
        }
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
