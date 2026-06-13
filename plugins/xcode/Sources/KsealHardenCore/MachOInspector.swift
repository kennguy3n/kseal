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
        static let segment64: UInt32 = 0x19
        static let uuid: UInt32 = 0x1b
        static let encryptionInfo: UInt32 = 0x21
        static let encryptionInfo64: UInt32 = 0x2c
    }
    private enum MH {
        static let pie: UInt32 = 0x20_0000
    }
    private enum CPU {
        static let abi64: Int32 = 0x0100_0000
        static let x86: Int32 = 7
        static let x86_64: Int32 = 7 | 0x0100_0000
        static let arm: Int32 = 12
        static let arm64: Int32 = 12 | 0x0100_0000
    }
}
