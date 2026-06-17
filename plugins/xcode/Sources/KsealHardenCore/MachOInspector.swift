import Foundation

public enum MachOInspectorError: Error, CustomStringConvertible {
    case binaryMissing(String)
    case notMachO
    case truncated
    case unsupported(String)

    public var description: String {
        switch self {
        case .binaryMissing(let path): return "binary not found: \(path)"
        case .notMachO: return "not a Mach-O binary"
        case .truncated: return "Mach-O binary is truncated or malformed"
        case .unsupported(let detail): return "unsupported Mach-O structure: \(detail)"
        }
    }
}

/// Computes Mach-O **section-hash integrity** evidence for a linked binary using
/// nothing but public, documented file-format parsing — no private API, no code
/// signing manipulation, App Store safe.
///
/// For every architecture slice it records a SHA-256 over each section's file
/// bytes, a SHA-256 over the whole load-command region, and the load-command
/// shape (count/size) plus PIE/encryption/UUID flags. Baked into the build
/// proof, this lets the runtime recompute the same digests from its own mapped
/// image and detect post-build tampering (patched sections, swapped load
/// commands) without trusting the OS's signature check alone.
///
/// The parser is endianness- and width-aware (32/64-bit, thin and fat) and fully
/// bounds-checked: malformed input throws rather than reading out of range.
public struct MachOInspector {
    public init() {}

    public func inspect(binaryAt url: URL) throws -> BuildProofManifest.Integrity {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw MachOInspectorError.binaryMissing(url.path)
        }
        let data = try Data(contentsOf: url)
        return try inspect(data: data)
    }

    // MARK: - Exploit-mitigation posture

    /// Per-slice exploit-mitigation posture parsed from the real Mach-O headers,
    /// load commands and symbol string table — PIE, non-exec stack/heap, code
    /// signature, FairPlay encryption, dyld-insertion restriction, stack canary
    /// and FORTIFY. Mirrors the Android ELF posture so both planes surface a
    /// consistent, per-binary report. Verification is real (parsed), never
    /// asserted; what cannot be determined (e.g. a fully stripped symbol table)
    /// is reported `indeterminate` rather than silently "absent".
    public func posture(binaryAt url: URL) throws -> Posture {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw MachOInspectorError.binaryMissing(url.path)
        }
        return try posture(data: try Data(contentsOf: url))
    }

    public func posture(data: Data) throws -> Posture {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else { throw MachOInspectorError.notMachO }
        let leading = readBE32(bytes, 0)
        switch leading {
        case Magic.fat, Magic.fat64:
            return try postureFat(bytes, is64: leading == Magic.fat64)
        default:
            return Posture(slices: [try postureThin(bytes, fileOffset: 0, fileSize: bytes.count)])
        }
    }

    // MARK: - String-obfuscation posture (Phase 5.2)

    /// Verifies whether the linked kseal trust-core binary still carries its
    /// sensitive string literals in plaintext.
    ///
    /// This is the Apple-side mirror of the Android plugin's
    /// `NativeStringObfuscationInspector` and the Rust core's compile-time
    /// `obfuscate-strings` feature (see `sdk/rust-core/kseal-core/src/obfuscate.rs`).
    /// The Rust static library that the XCFramework links is the same trust core;
    /// when it is built hardened (`KSEAL_OBFUSCATE_STRINGS=1`) the sensitive
    /// literals are absent from the Mach-O image. This method *verifies* and
    /// records that posture — it does not transform the binary — so the build
    /// proof carries evidence of whether the hardened core was shipped.
    ///
    /// Detection is a pure, deterministic ASCII substring scan over the whole
    /// file (thin or fat), exactly like the Android counterpart. The posture is
    /// asserted only for the kseal core, identified by its exported C ABI symbol
    /// prefix (`kseal_`, which stays plaintext by design — those names are linked
    /// by the Swift bridge). Binaries we do not build are reported
    /// `.notApplicable` rather than falsely "clean".
    public func stringObfuscation(binaryAt url: URL) throws -> StringObfuscation {
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw MachOInspectorError.binaryMissing(url.path)
        }
        return stringObfuscation(data: try Data(contentsOf: url))
    }

    /// Pure scanning core, exposed for unit tests.
    public func stringObfuscation(data: Data) -> StringObfuscation {
        let bytes = [UInt8](data)
        guard containsAscii(bytes, Self.ksealExportMarker) else {
            return StringObfuscation(
                status: .notApplicable,
                isKsealCore: false,
                markersFound: [],
                notes: ["no kseal_* exports; not the trust core, string posture not asserted"]
            )
        }
        let found = Self.stringSentinels.filter { containsAscii(bytes, $0) }
        if found.isEmpty {
            return StringObfuscation(status: .obfuscated, isKsealCore: true, markersFound: [], notes: [])
        }
        return StringObfuscation(
            status: .plaintext,
            isKsealCore: true,
            markersFound: found,
            notes: [
                "trust-core string literals present in plaintext; build the static library "
                    + "with the obfuscate-strings feature (KSEAL_OBFUSCATE_STRINGS=1) to harden them"
            ]
        )
    }

    private func postureFat(_ bytes: [UInt8], is64: Bool) throws -> Posture {
        let count = Int(readBE32(bytes, 4))
        var slices: [Posture.Slice] = []
        var cursor = 8
        let archSize = is64 ? 32 : 20
        for _ in 0..<count {
            guard cursor + archSize <= bytes.count else { throw MachOInspectorError.truncated }
            let offset = is64 ? Int(readBE64(bytes, cursor + 8)) : Int(readBE32(bytes, cursor + 8))
            let size = is64 ? Int(readBE64(bytes, cursor + 16)) : Int(readBE32(bytes, cursor + 12))
            guard offset >= 0, size >= 0, offset + size <= bytes.count else { throw MachOInspectorError.truncated }
            slices.append(try postureThin(bytes, fileOffset: offset, fileSize: size))
            cursor += archSize
        }
        return Posture(slices: slices.sorted { $0.arch < $1.arch })
    }

    private func postureThin(_ bytes: [UInt8], fileOffset base: Int, fileSize: Int) throws -> Posture.Slice {
        guard base + 4 <= bytes.count else { throw MachOInspectorError.truncated }
        let raw = readBE32(bytes, base)
        let (is64, little): (Bool, Bool)
        switch raw {
        case Magic.thin32BE: (is64, little) = (false, false)
        case Magic.thin32LE: (is64, little) = (false, true)
        case Magic.thin64BE: (is64, little) = (true, false)
        case Magic.thin64LE: (is64, little) = (true, true)
        default: throw MachOInspectorError.notMachO
        }
        let headerSize = is64 ? 32 : 28
        guard base + headerSize <= bytes.count else { throw MachOInspectorError.truncated }
        func u32(_ at: Int) -> UInt32 { little ? readLE32(bytes, at) : readBE32(bytes, at) }

        let cpuType = Int32(bitPattern: u32(base + 4))
        let fileType = u32(base + 12)
        let ncmds = Int(u32(base + 16))
        let sizeOfCmds = Int(u32(base + 20))
        let flags = u32(base + 24)

        let lcStart = base + headerSize
        let lcEnd = lcStart + sizeOfCmds
        guard lcEnd <= bytes.count, lcEnd <= base + fileSize else { throw MachOInspectorError.truncated }

        var hasCodeSignature = false
        var encrypted = false
        var hasRestrict = false
        var symtab: (stroff: Int, strsize: Int)?

        var cursor = lcStart
        for _ in 0..<ncmds {
            guard cursor + 8 <= lcEnd else { throw MachOInspectorError.truncated }
            let cmd = u32(cursor)
            let cmdSize = Int(u32(cursor + 4))
            guard cmdSize >= 8, cursor + cmdSize <= lcEnd else { throw MachOInspectorError.truncated }
            switch cmd {
            case LC.segment, LC.segment64:
                if segmentHasRestrictSection(bytes, cmdStart: cursor, is64: cmd == LC.segment64, u32: u32) {
                    hasRestrict = true
                }
            case LC.codeSignature:
                hasCodeSignature = true
            case LC.encryptionInfo, LC.encryptionInfo64:
                if cursor + 20 <= lcEnd, u32(cursor + 16) != 0 { encrypted = true }
            case LC.symtab:
                if cursor + 24 <= lcEnd {
                    symtab = (stroff: Int(u32(cursor + 16)), strsize: Int(u32(cursor + 20)))
                }
            default:
                break
            }
            cursor += cmdSize
        }

        // Search the real symbol string table for the canary/FORTIFY imports.
        var canaryFound = false
        var fortifyFound = false
        var symbolsReadable = false
        if let st = symtab, st.strsize > 0 {
            let start = base + st.stroff
            let end = start + st.strsize
            if start >= base, end <= bytes.count, end <= base + fileSize {
                symbolsReadable = true
                let table = Array(bytes[start..<end])
                canaryFound = Self.stackCanarySymbols.contains { containsAscii(table, $0) }
                fortifyFound = Self.fortifySymbols.contains { containsAscii(table, $0) }
            }
        }

        let isExecutable = fileType == FileType.execute
        var notes: [String] = []

        let pie: PostureStatus
        if isExecutable {
            pie = (flags & MH.pie) != 0 ? .enabled : .absent
            if pie == .absent { notes.append("main executable is not position-independent (MH_PIE clear)") }
        } else {
            pie = .unsupported // dylibs/bundles are inherently position-independent
        }

        let nxStack: PostureStatus = (flags & MH.allowStackExecution) != 0 ? .absent : .enabled
        if nxStack == .absent { notes.append("executable stack permitted (MH_ALLOW_STACK_EXECUTION set)") }

        let nxHeap: PostureStatus = (flags & MH.noHeapExecution) != 0 ? .enabled : .indeterminate

        let codeSignature: PostureStatus = hasCodeSignature ? .enabled : .absent
        if codeSignature == .absent { notes.append("no LC_CODE_SIGNATURE load command") }

        let restrict: PostureStatus
        if hasRestrict {
            restrict = .enabled
        } else if isExecutable {
            restrict = .absent
        } else {
            restrict = .unsupported
        }

        let stackCanary: PostureStatus
        let fortify: PostureStatus
        if symbolsReadable {
            stackCanary = canaryFound ? .enabled : .absent
            fortify = fortifyFound ? .enabled : .absent
        } else {
            stackCanary = .indeterminate
            fortify = .indeterminate
            notes.append("symbol string table unavailable; canary/FORTIFY indeterminate")
        }

        return Posture.Slice(
            arch: archName(cpuType),
            fileType: fileTypeName(fileType),
            pie: pie,
            nxStack: nxStack,
            nxHeap: nxHeap,
            codeSignature: codeSignature,
            encrypted: encrypted,
            restrict: restrict,
            stackCanary: stackCanary,
            fortify: fortify,
            notes: notes
        )
    }

    private func segmentHasRestrictSection(
        _ bytes: [UInt8], cmdStart: Int, is64: Bool, u32: (Int) -> UInt32
    ) -> Bool {
        let segName = readFixedString(bytes, cmdStart + 8, 16)
        guard segName == "__RESTRICT" else { return false }
        let nsectsOffset = is64 ? 64 : 48
        let segHeaderSize = is64 ? 72 : 56
        let sectSize = is64 ? 80 : 68
        guard cmdStart + nsectsOffset + 4 <= bytes.count else { return false }
        let nsects = Int(u32(cmdStart + nsectsOffset))
        var sectCursor = cmdStart + segHeaderSize
        for _ in 0..<nsects {
            guard sectCursor + sectSize <= bytes.count else { return false }
            if readFixedString(bytes, sectCursor, 16) == "__restrict" { return true }
            sectCursor += sectSize
        }
        return false
    }

    /// True if the C-string [needle] (ASCII) occurs in the symbol string table blob.
    private func containsAscii(_ haystack: [UInt8], _ needle: String) -> Bool {
        let n = Array(needle.utf8)
        if n.isEmpty || n.count > haystack.count { return false }
        var i = 0
        let last = haystack.count - n.count
        while i <= last {
            var j = 0
            while j < n.count, haystack[i + j] == n[j] { j += 1 }
            if j == n.count { return true }
            i += 1
        }
        return false
    }

    public func inspect(data: Data) throws -> BuildProofManifest.Integrity {
        let bytes = [UInt8](data)
        guard bytes.count >= 4 else { throw MachOInspectorError.notMachO }

        let leading = readBE32(bytes, 0)
        switch leading {
        case Magic.fat, Magic.fat64:
            return try inspectFat(bytes, is64: leading == Magic.fat64)
        default:
            let slice = try inspectThin(bytes, fileOffset: 0, fileSize: bytes.count)
            return BuildProofManifest.Integrity(slices: [slice])
        }
    }

    // MARK: - Fat (universal) binaries

    /// Fat headers are always stored big-endian on disk.
    private func inspectFat(_ bytes: [UInt8], is64: Bool) throws -> BuildProofManifest.Integrity {
        let count = Int(readBE32(bytes, 4))
        var slices: [BuildProofManifest.Integrity.Slice] = []
        var cursor = 8
        let archSize = is64 ? 32 : 20
        for _ in 0..<count {
            guard cursor + archSize <= bytes.count else { throw MachOInspectorError.truncated }
            let offset: Int
            let size: Int
            if is64 {
                offset = Int(readBE64(bytes, cursor + 8))
                size = Int(readBE64(bytes, cursor + 16))
            } else {
                offset = Int(readBE32(bytes, cursor + 8))
                size = Int(readBE32(bytes, cursor + 12))
            }
            guard offset >= 0, size >= 0, offset + size <= bytes.count else { throw MachOInspectorError.truncated }
            slices.append(try inspectThin(bytes, fileOffset: offset, fileSize: size))
            cursor += archSize
        }
        return BuildProofManifest.Integrity(slices: slices.sorted { $0.arch < $1.arch })
    }

    // MARK: - Thin (single-architecture) slices

    private func inspectThin(_ bytes: [UInt8], fileOffset base: Int, fileSize: Int) throws -> BuildProofManifest.Integrity.Slice {
        guard base + 4 <= bytes.count else { throw MachOInspectorError.truncated }
        let raw = readBE32(bytes, base)
        let (is64, little): (Bool, Bool)
        switch raw {
        case Magic.thin32BE: (is64, little) = (false, false)
        case Magic.thin32LE: (is64, little) = (false, true)
        case Magic.thin64BE: (is64, little) = (true, false)
        case Magic.thin64LE: (is64, little) = (true, true)
        default: throw MachOInspectorError.notMachO
        }

        let headerSize = is64 ? 32 : 28
        guard base + headerSize <= bytes.count else { throw MachOInspectorError.truncated }
        func u32(_ at: Int) -> UInt32 { little ? readLE32(bytes, at) : readBE32(bytes, at) }
        func u64(_ at: Int) -> UInt64 { little ? readLE64(bytes, at) : readBE64(bytes, at) }

        let cpuType = Int32(bitPattern: u32(base + 4))
        let fileType = u32(base + 12)
        let ncmds = Int(u32(base + 16))
        let sizeOfCmds = Int(u32(base + 20))
        let flags = u32(base + 24)

        let lcStart = base + headerSize
        let lcEnd = lcStart + sizeOfCmds
        guard lcEnd <= bytes.count else { throw MachOInspectorError.truncated }

        var sections: [BuildProofManifest.Integrity.SectionHash] = []
        var encrypted = false
        var uuid = ""

        var cursor = lcStart
        for _ in 0..<ncmds {
            guard cursor + 8 <= lcEnd else { throw MachOInspectorError.truncated }
            let cmd = u32(cursor)
            let cmdSize = Int(u32(cursor + 4))
            guard cmdSize >= 8, cursor + cmdSize <= lcEnd else { throw MachOInspectorError.truncated }

            switch cmd {
            case LC.segment, LC.segment64:
                try collectSections(
                    bytes, cmdStart: cursor, is64: cmd == LC.segment64,
                    sliceBase: base, sliceSize: fileSize, u32: u32, u64: u64, into: &sections
                )
            case LC.uuid:
                if cursor + 24 <= lcEnd { uuid = HexEncoding.encode(Array(bytes[(cursor + 8)..<(cursor + 24)])) }
            case LC.encryptionInfo, LC.encryptionInfo64:
                if cursor + 20 <= lcEnd, u32(cursor + 16) != 0 { encrypted = true }
            default:
                break
            }
            cursor += cmdSize
        }

        let lcHash = SHA256.hexDigest(Array(bytes[lcStart..<lcEnd]))
        return BuildProofManifest.Integrity.Slice(
            arch: archName(cpuType),
            fileType: fileTypeName(fileType),
            pie: (flags & MH.pie) != 0,
            encrypted: encrypted,
            uuid: uuid,
            loadCommandCount: ncmds,
            loadCommandsSize: sizeOfCmds,
            loadCommandsHash: lcHash,
            sections: sections.sorted { ($0.segment, $0.section) < ($1.segment, $1.section) }
        )
    }

    private func collectSections(
        _ bytes: [UInt8],
        cmdStart: Int,
        is64: Bool,
        sliceBase: Int,
        sliceSize: Int,
        u32: (Int) -> UInt32,
        u64: (Int) -> UInt64,
        into sections: inout [BuildProofManifest.Integrity.SectionHash]
    ) throws {
        // segment_command(_64): nsects sits after the 16-byte segname + 4/8-byte
        // address/size quad; section records follow the command header.
        let nsectsOffset = is64 ? 64 : 48
        let segHeaderSize = is64 ? 72 : 56
        let sectSize = is64 ? 80 : 68
        let segName = readFixedString(bytes, cmdStart + 8, 16)
        let nsects = Int(u32(cmdStart + nsectsOffset))

        var sectCursor = cmdStart + segHeaderSize
        for _ in 0..<nsects {
            guard sectCursor + sectSize <= bytes.count else { throw MachOInspectorError.truncated }
            let sectName = readFixedString(bytes, sectCursor, 16)
            let size: Int
            let offset: Int
            if is64 {
                size = Int(u64(sectCursor + 40))
                offset = Int(u32(sectCursor + 48))
            } else {
                size = Int(u32(sectCursor + 36))
                offset = Int(u32(sectCursor + 40))
            }

            // S_ZEROFILL (and friends) occupy no file range: offset is 0 / unmapped.
            let hash: String
            if offset == 0 || size == 0 {
                hash = ""
            } else {
                let start = sliceBase + offset
                let end = start + size
                guard start >= sliceBase, end <= sliceBase + sliceSize, end <= bytes.count else {
                    throw MachOInspectorError.truncated
                }
                hash = SHA256.hexDigest(Array(bytes[start..<end]))
            }
            sections.append(.init(segment: segName, section: sectName, size: size, hash: hash))
            sectCursor += sectSize
        }
    }

    // MARK: - Name mappings

    private func archName(_ cpuType: Int32) -> String {
        switch cpuType {
        case CPU.arm64: return "arm64"
        case CPU.arm: return "arm"
        case CPU.x86_64: return "x86_64"
        case CPU.x86: return "x86"
        default: return "cpu(\(cpuType))"
        }
    }

    private func fileTypeName(_ type: UInt32) -> String {
        switch type {
        case 1: return "object"
        case 2: return "execute"
        case 6: return "dylib"
        case 8: return "bundle"
        case 10: return "dsym"
        default: return "type(\(type))"
        }
    }

    // MARK: - Primitive readers (bounds checked by callers)

    private func readFixedString(_ bytes: [UInt8], _ at: Int, _ len: Int) -> String {
        let slice = bytes[at..<min(at + len, bytes.count)]
        let trimmed = slice.prefix { $0 != 0 }
        return String(decoding: trimmed, as: UTF8.self)
    }

    private func readBE32(_ b: [UInt8], _ i: Int) -> UInt32 {
        (UInt32(b[i]) << 24) | (UInt32(b[i + 1]) << 16) | (UInt32(b[i + 2]) << 8) | UInt32(b[i + 3])
    }
    private func readLE32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | (UInt32(b[i + 1]) << 8) | (UInt32(b[i + 2]) << 16) | (UInt32(b[i + 3]) << 24)
    }
    private func readBE64(_ b: [UInt8], _ i: Int) -> UInt64 {
        (UInt64(readBE32(b, i)) << 32) | UInt64(readBE32(b, i + 4))
    }
    private func readLE64(_ b: [UInt8], _ i: Int) -> UInt64 {
        UInt64(readLE32(b, i)) | (UInt64(readLE32(b, i + 4)) << 32)
    }

    private enum Magic {
        static let thin32BE: UInt32 = 0xfeed_face
        static let thin32LE: UInt32 = 0xcefa_edfe
        static let thin64BE: UInt32 = 0xfeed_facf
        static let thin64LE: UInt32 = 0xcffa_edfe
        static let fat: UInt32 = 0xcafe_babe
        static let fat64: UInt32 = 0xcafe_babf
    }
    private enum LC {
        static let segment: UInt32 = 0x1
        static let symtab: UInt32 = 0x2
        static let segment64: UInt32 = 0x19
        static let uuid: UInt32 = 0x1b
        static let codeSignature: UInt32 = 0x1d
        static let encryptionInfo: UInt32 = 0x21
        static let encryptionInfo64: UInt32 = 0x2c
    }
    private enum MH {
        static let allowStackExecution: UInt32 = 0x2_0000
        static let pie: UInt32 = 0x20_0000
        static let noHeapExecution: UInt32 = 0x100_0000
    }
    private enum FileType {
        static let execute: UInt32 = 2
    }

    /// Exported C ABI symbol prefix of the kseal trust core. Its presence marks
    /// a binary as "ours" so the string posture is asserted only for the core;
    /// these names stay in clear by design (the Swift bridge links them).
    private static let ksealExportMarker = "kseal_"
    /// Literals that are unique to the trust core's obfuscatable call sites and
    /// do *not* appear in proto-generated reflection metadata. Their absence in a
    /// kseal binary means the hardened (obfuscate-strings) core was shipped. Kept
    /// byte-identical to the Android `NativeStringObfuscationInspector` sentinels.
    private static let stringSentinels = [
        "config signature verification failed",
        "network_mitm",
        "app_integrity",
    ]

    /// Undefined imports the compiler emits when stack-protector is on.
    private static let stackCanarySymbols = ["___stack_chk_fail", "___stack_chk_guard"]
    /// A representative set of `_FORTIFY_SOURCE` checked-builtin imports.
    private static let fortifySymbols = [
        "___memcpy_chk", "___memmove_chk", "___memset_chk",
        "___strcpy_chk", "___strncpy_chk", "___strcat_chk", "___strncat_chk",
        "___sprintf_chk", "___snprintf_chk", "___vsnprintf_chk",
    ]
    private enum CPU {
        static let abi64: Int32 = 0x0100_0000
        static let x86: Int32 = 7
        static let x86_64: Int32 = 7 | 0x0100_0000
        static let arm: Int32 = 12
        static let arm64: Int32 = 12 | 0x0100_0000
    }

    /// Outcome of a single mitigation check.
    public enum PostureStatus: String, Codable, Equatable {
        /// The mitigation is present.
        case enabled
        /// The mitigation is applicable to this binary but not present (a finding).
        case absent
        /// The mitigation does not apply to this binary kind (e.g. PIE on a dylib).
        case unsupported
        /// The mitigation could not be determined from the available data.
        case indeterminate
    }

    /// A clear, per-binary exploit-mitigation posture report.
    public struct Posture: Codable, Equatable {
        public var format: String
        public var slices: [Slice]

        public init(format: String = "macho", slices: [Slice]) {
            self.format = format
            self.slices = slices
        }

        /// True only when every slice has a complete, finding-free posture.
        public var allHardened: Bool { !slices.isEmpty && slices.allSatisfy { $0.hardened } }

        public struct Slice: Codable, Equatable {
            public var arch: String
            public var fileType: String
            public var pie: PostureStatus
            public var nxStack: PostureStatus
            public var nxHeap: PostureStatus
            public var codeSignature: PostureStatus
            public var encrypted: Bool
            public var restrict: PostureStatus
            public var stackCanary: PostureStatus
            public var fortify: PostureStatus
            public var notes: [String]

            public init(
                arch: String,
                fileType: String,
                pie: PostureStatus,
                nxStack: PostureStatus,
                nxHeap: PostureStatus,
                codeSignature: PostureStatus,
                encrypted: Bool,
                restrict: PostureStatus,
                stackCanary: PostureStatus,
                fortify: PostureStatus,
                notes: [String]
            ) {
                self.arch = arch
                self.fileType = fileType
                self.pie = pie
                self.nxStack = nxStack
                self.nxHeap = nxHeap
                self.codeSignature = codeSignature
                self.encrypted = encrypted
                self.restrict = restrict
                self.stackCanary = stackCanary
                self.fortify = fortify
                self.notes = notes
            }

            /// No mitigation that *applies* to this slice is absent. `unsupported`
            /// and `indeterminate` are not counted as findings (we never assert).
            public var hardened: Bool {
                ![pie, nxStack, codeSignature, restrict, stackCanary, fortify].contains(.absent)
            }
        }
    }

    /// Outcome of the trust-core string-obfuscation check. Wire values are kept
    /// byte-identical to the Android plugin so a build-proof reader sees a single
    /// vocabulary across both planes.
    public enum StringObfuscationStatus: String, Codable, Equatable {
        /// kseal core with none of the sensitive literals in plaintext.
        case obfuscated
        /// kseal core that still exposes one or more sensitive literals.
        case plaintext
        /// Not a kseal binary; posture is not asserted.
        case notApplicable = "not-applicable"
        /// The binary could not be read; posture is unknown.
        case indeterminate
    }

    /// String-obfuscation posture for one linked binary. Mirrors the Android
    /// `NativeStringObfuscationInspector.Result` so the build proof records a
    /// consistent, cross-platform shape.
    public struct StringObfuscation: Codable, Equatable {
        public var status: StringObfuscationStatus
        public var isKsealCore: Bool
        public var markersFound: [String]
        public var notes: [String]

        public init(
            status: StringObfuscationStatus,
            isKsealCore: Bool,
            markersFound: [String],
            notes: [String]
        ) {
            self.status = status
            self.isKsealCore = isKsealCore
            self.markersFound = markersFound
            self.notes = notes
        }
    }
}
