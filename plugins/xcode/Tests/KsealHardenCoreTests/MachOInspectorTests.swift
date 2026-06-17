import XCTest
@testable import KsealHardenCore

final class MachOInspectorTests: XCTestCase {

    func testThinArm64SectionAndLoadCommandHashes() throws {
        let textData = Array("the quick brown fox".utf8)
        let builder = MachOBuilder(arch: .arm64, fileType: 2, pie: true, uuid: uuid16(0xAB))
        builder.addSegment(
            "__TEXT",
            sections: [
                .data("__text", "__TEXT", textData),
                .zerofill("__common", "__DATA", size: 4096),
            ]
        )
        let data = builder.build()

        let integrity = try MachOInspector().inspect(data: data)
        XCTAssertEqual(integrity.format, "macho")
        XCTAssertEqual(integrity.slices.count, 1)

        let slice = integrity.slices[0]
        XCTAssertEqual(slice.arch, "arm64")
        XCTAssertEqual(slice.fileType, "execute")
        XCTAssertTrue(slice.pie)
        XCTAssertFalse(slice.encrypted)
        XCTAssertEqual(slice.uuid, hex(uuid16(0xAB)))
        XCTAssertEqual(slice.loadCommandCount, builder.commandCount)
        XCTAssertEqual(slice.loadCommandsSize, builder.commandsSize)
        XCTAssertFalse(slice.loadCommandsHash.isEmpty)

        // Sections are sorted by (segment, section); each carries the right hash.
        XCTAssertEqual(slice.sections.count, 2)
        let text = slice.sections.first { $0.section == "__text" }!
        XCTAssertEqual(text.hash, SHA256.hexDigest(textData))
        XCTAssertEqual(text.size, textData.count)

        let bss = slice.sections.first { $0.section == "__common" }!
        XCTAssertEqual(bss.hash, "", "zero-fill section must have no file-content hash")
        XCTAssertEqual(bss.size, 4096)
    }

    func testTamperingASectionChangesItsHashOnly() throws {
        let builder = MachOBuilder(arch: .arm64, fileType: 6, pie: false, uuid: uuid16(0x11))
        builder.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("original".utf8))])
        let original = try MachOInspector().inspect(data: builder.build())

        let builder2 = MachOBuilder(arch: .arm64, fileType: 6, pie: false, uuid: uuid16(0x11))
        builder2.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("tampered".utf8))])
        let tampered = try MachOInspector().inspect(data: builder2.build())

        XCTAssertNotEqual(original.slices[0].sections[0].hash, tampered.slices[0].sections[0].hash)
    }

    func testEncryptedSliceIsReported() throws {
        let builder = MachOBuilder(arch: .arm64, fileType: 2, pie: true, uuid: nil, cryptId: 1)
        builder.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("x".utf8))])
        let integrity = try MachOInspector().inspect(data: builder.build())
        XCTAssertTrue(integrity.slices[0].encrypted)
        XCTAssertEqual(integrity.slices[0].uuid, "", "no LC_UUID => empty uuid")
    }

    func testFatBinaryProducesOneSortedSlicePerArch() throws {
        let arm = MachOBuilder(arch: .arm64, fileType: 2, pie: true, uuid: uuid16(1))
        arm.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("arm".utf8))])
        let x86 = MachOBuilder(arch: .x86_64, fileType: 2, pie: true, uuid: uuid16(2))
        x86.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("x86".utf8))])

        let fat = MachOBuilder.fat([arm.build(), x86.build()])
        let integrity = try MachOInspector().inspect(data: fat)

        XCTAssertEqual(integrity.slices.map { $0.arch }, ["arm64", "x86_64"])
    }

    func testRejectsNonMachOInput() {
        XCTAssertThrowsError(try MachOInspector().inspect(data: Data("not a mach-o binary".utf8))) { error in
            guard case MachOInspectorError.notMachO = error else { return XCTFail("expected notMachO, got \(error)") }
        }
    }

    func testTruncatedBinaryThrows() {
        // Valid 64-bit magic but no room for the header.
        var bytes: [UInt8] = [0xcf, 0xfa, 0xed, 0xfe]
        bytes.append(contentsOf: [0, 0, 0, 0])
        XCTAssertThrowsError(try MachOInspector().inspect(data: Data(bytes)))
    }

    func testIntegrityRoundTripsThroughManifest() throws {
        let builder = MachOBuilder(arch: .arm64, fileType: 6, pie: true, uuid: uuid16(0x42))
        builder.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("payload".utf8))])
        let integrity = try MachOInspector().inspect(data: builder.build())

        let manifest = BuildProofManifest(
            sdkVersion: "0.1.0", buildHash: "deadbeef", versionName: "1.0", versionCode: 1,
            polymorphism: .init(seedDigest: "00"), toolVersions: [:], transforms: [], modules: [],
            provenance: .init(generatedAt: "t", generator: "g", host: "h"),
            integrity: integrity
        )
        let decoded = try BuildProofManifest.decode(from: try manifest.jsonData())
        XCTAssertEqual(decoded.integrity, integrity)
    }

    func testManifestWithoutIntegrityOmitsKeyAndDecodes() throws {
        let manifest = BuildProofManifest(
            sdkVersion: "0.1.0", buildHash: "h", versionName: "1.0", versionCode: 1,
            polymorphism: .init(seedDigest: "00"), toolVersions: [:], transforms: [], modules: [],
            provenance: .init(generatedAt: "t", generator: "g", host: "h")
        )
        let json = try manifest.jsonString()
        XCTAssertFalse(json.contains("integrity"), "absent integrity must not appear in JSON (backward compatible)")
        XCTAssertNil(try BuildProofManifest.decode(from: Data(json.utf8)).integrity)
    }

    // MARK: posture

    func testPostureReportsAFullyHardenedExecutable() throws {
        let builder = MachOBuilder(
            arch: .arm64, fileType: 2, pie: true, uuid: uuid16(1),
            extraFlags: 0x100_0000, // MH_NO_HEAP_EXECUTION
            codeSignature: true,
            symbolStrings: ["___stack_chk_fail", "___memcpy_chk", "_main"]
        )
        builder.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("code".utf8))])
        builder.addSegment("__RESTRICT", sections: [.data("__restrict", "__RESTRICT", [])])

        let posture = try MachOInspector().posture(data: builder.build())
        XCTAssertEqual(posture.format, "macho")
        XCTAssertEqual(posture.slices.count, 1)
        let s = posture.slices[0]
        XCTAssertEqual(s.arch, "arm64")
        XCTAssertEqual(s.pie, .enabled)
        XCTAssertEqual(s.nxStack, .enabled)
        XCTAssertEqual(s.nxHeap, .enabled)
        XCTAssertEqual(s.codeSignature, .enabled)
        XCTAssertEqual(s.restrict, .enabled)
        XCTAssertEqual(s.stackCanary, .enabled)
        XCTAssertEqual(s.fortify, .enabled)
        XCTAssertTrue(s.hardened)
        XCTAssertTrue(posture.allHardened)
        XCTAssertTrue(s.notes.isEmpty)
    }

    func testPostureFlagsAbsentMitigationsAsFindings() throws {
        // Non-PIE executable, executable stack, no code signature, no symbol table.
        let builder = MachOBuilder(
            arch: .x86_64, fileType: 2, pie: false, uuid: nil,
            extraFlags: 0x2_0000 // MH_ALLOW_STACK_EXECUTION
        )
        builder.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("x".utf8))])

        let s = try MachOInspector().posture(data: builder.build()).slices[0]
        XCTAssertEqual(s.pie, .absent)
        XCTAssertEqual(s.nxStack, .absent)
        XCTAssertEqual(s.codeSignature, .absent)
        XCTAssertEqual(s.restrict, .absent)
        // No symbol table => canary/FORTIFY cannot be asserted (not silently absent).
        XCTAssertEqual(s.stackCanary, .indeterminate)
        XCTAssertEqual(s.fortify, .indeterminate)
        XCTAssertFalse(s.hardened)
        XCTAssertFalse(s.notes.isEmpty)
    }

    func testPostureMarksPieAndRestrictUnsupportedForDylibs() throws {
        let builder = MachOBuilder(
            arch: .arm64, fileType: 6, pie: false, uuid: uuid16(2),
            codeSignature: true,
            symbolStrings: ["___stack_chk_guard", "___strcpy_chk"]
        )
        builder.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("lib".utf8))])

        let s = try MachOInspector().posture(data: builder.build()).slices[0]
        XCTAssertEqual(s.fileType, "dylib")
        XCTAssertEqual(s.pie, .unsupported, "PIE is a main-executable concept")
        XCTAssertEqual(s.restrict, .unsupported, "__RESTRICT applies to executables")
        XCTAssertEqual(s.stackCanary, .enabled)
        XCTAssertEqual(s.fortify, .enabled)
        XCTAssertEqual(s.codeSignature, .enabled)
        XCTAssertTrue(s.hardened, "unsupported mitigations are not findings")
    }

    func testPostureDetectsMissingCanaryWhenSymbolsPresent() throws {
        // A readable symbol table without the canary import => canary absent (finding).
        let builder = MachOBuilder(
            arch: .arm64, fileType: 2, pie: true, uuid: uuid16(3),
            codeSignature: true,
            symbolStrings: ["_main", "_printf"]
        )
        builder.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("z".utf8))])

        let s = try MachOInspector().posture(data: builder.build()).slices[0]
        XCTAssertEqual(s.stackCanary, .absent)
        XCTAssertEqual(s.fortify, .absent)
        XCTAssertFalse(s.hardened)
    }

    func testPostureSortsFatSlicesAndRoundTripsThroughManifest() throws {
        let arm = MachOBuilder(arch: .arm64, fileType: 2, pie: true, uuid: uuid16(1), codeSignature: true,
                               symbolStrings: ["___stack_chk_fail", "___memcpy_chk"])
        arm.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("arm".utf8))])
        arm.addSegment("__RESTRICT", sections: [.data("__restrict", "__RESTRICT", [])])
        let x86 = MachOBuilder(arch: .x86_64, fileType: 2, pie: true, uuid: uuid16(2), codeSignature: true,
                               symbolStrings: ["___stack_chk_fail", "___memcpy_chk"])
        x86.addSegment("__TEXT", sections: [.data("__text", "__TEXT", Array("x86".utf8))])
        x86.addSegment("__RESTRICT", sections: [.data("__restrict", "__RESTRICT", [])])

        let posture = try MachOInspector().posture(data: MachOBuilder.fat([arm.build(), x86.build()]))
        XCTAssertEqual(posture.slices.map { $0.arch }, ["arm64", "x86_64"])
        XCTAssertTrue(posture.allHardened)

        let manifest = BuildProofManifest(
            sdkVersion: "0.1.0", buildHash: "h", versionName: "1.0", versionCode: 1,
            polymorphism: .init(seedDigest: "00"), toolVersions: [:], transforms: [], modules: [],
            provenance: .init(generatedAt: "t", generator: "g", host: "h"),
            posture: posture
        )
        let decoded = try BuildProofManifest.decode(from: try manifest.jsonData())
        XCTAssertEqual(decoded.posture, posture)
    }

    // MARK: String-obfuscation posture (Phase 5.2)

    func testStringObfuscationReportsHardenedKsealCore() throws {
        // kseal core (has kseal_* exports) with none of the sensitive literals
        // in plaintext => the obfuscate-strings build was shipped.
        let data = ksealCore(embedding: ["kseal_attest", "kseal_evaluate", "emulator", "debugger"])
        let report = MachOInspector().stringObfuscation(data: data)
        XCTAssertEqual(report.status, .obfuscated)
        XCTAssertTrue(report.isKsealCore)
        XCTAssertTrue(report.markersFound.isEmpty)
    }

    func testStringObfuscationFlagsPlaintextTrustCore() throws {
        let data = ksealCore(embedding: ["kseal_attest", "config signature verification failed", "network_mitm"])
        let report = MachOInspector().stringObfuscation(data: data)
        XCTAssertEqual(report.status, .plaintext)
        XCTAssertTrue(report.isKsealCore)
        XCTAssertEqual(report.markersFound, ["config signature verification failed", "network_mitm"])
        XCTAssertFalse(report.notes.isEmpty)
    }

    func testStringObfuscationDoesNotAssertForForeignBinaries() throws {
        // No kseal_* export marker => not ours; posture not asserted even though a
        // sentinel-looking literal is present.
        let data = ksealCore(embedding: ["app_integrity", "libc_start_main"], includeMarker: false)
        let report = MachOInspector().stringObfuscation(data: data)
        XCTAssertEqual(report.status, .notApplicable)
        XCTAssertFalse(report.isKsealCore)
        XCTAssertTrue(report.markersFound.isEmpty)
    }

    func testStringObfuscationIgnoresAmbiguousTaxonomyTokens() throws {
        // Short detector tokens also appear in proto reflection metadata, so they
        // are not sentinels; a core carrying only those is still "obfuscated".
        let data = ksealCore(embedding: ["kseal_evaluate", "root", "debugger", "emulator"])
        XCTAssertEqual(MachOInspector().stringObfuscation(data: data).status, .obfuscated)
    }

    func testStringObfuscationWireValuesAreStable() {
        XCTAssertEqual(MachOInspector.StringObfuscationStatus.obfuscated.rawValue, "obfuscated")
        XCTAssertEqual(MachOInspector.StringObfuscationStatus.plaintext.rawValue, "plaintext")
        XCTAssertEqual(MachOInspector.StringObfuscationStatus.notApplicable.rawValue, "not-applicable")
        XCTAssertEqual(MachOInspector.StringObfuscationStatus.indeterminate.rawValue, "indeterminate")
    }

    // MARK: helpers

    /// Builds a thin arm64 dylib whose `__cstring` section carries `literals`
    /// (NUL-terminated), optionally including the kseal export marker so the
    /// binary is recognised as the trust core.
    private func ksealCore(embedding literals: [String], includeMarker: Bool = true) -> Data {
        var blob: [UInt8] = []
        if includeMarker {
            blob.append(contentsOf: Array("kseal_".utf8))
            blob.append(0)
        }
        for literal in literals {
            blob.append(contentsOf: Array(literal.utf8))
            blob.append(0)
        }
        let builder = MachOBuilder(arch: .arm64, fileType: 6, pie: false, uuid: uuid16(0x5A))
        builder.addSegment("__TEXT", sections: [.data("__cstring", "__TEXT", blob)])
        return builder.build()
    }

    private func uuid16(_ fill: UInt8) -> [UInt8] { Array(repeating: fill, count: 16) }
    private func hex(_ bytes: [UInt8]) -> String { HexEncoding.encode(bytes) }
}

/// Builds minimal but structurally valid little-endian Mach-O binaries for tests.
private final class MachOBuilder {
    enum Arch { case arm64, x86_64 }
    enum Section {
        case data(String, String, [UInt8])
        case zerofill(String, String, size: Int)
    }

    private let arch: Arch
    private let fileType: UInt32
    private let pie: Bool
    private let uuid: [UInt8]?
    private let cryptId: UInt32?
    private let extraFlags: UInt32
    private let codeSignature: Bool
    private let symbolStrings: [String]?
    private var segments: [(name: String, sections: [Section])] = []

    private(set) var commandCount = 0
    private(set) var commandsSize = 0

    init(
        arch: Arch,
        fileType: UInt32,
        pie: Bool,
        uuid: [UInt8]?,
        cryptId: UInt32? = nil,
        extraFlags: UInt32 = 0,
        codeSignature: Bool = false,
        symbolStrings: [String]? = nil
    ) {
        self.arch = arch
        self.fileType = fileType
        self.pie = pie
        self.uuid = uuid
        self.cryptId = cryptId
        self.extraFlags = extraFlags
        self.codeSignature = codeSignature
        self.symbolStrings = symbolStrings
    }

    func addSegment(_ name: String, sections: [Section]) {
        segments.append((name, sections))
    }

    func build() -> Data {
        var loadCommands: [[UInt8]] = []

        // The symbol string table is a NUL-prefixed, NUL-separated blob.
        var stringTable: [UInt8] = []
        if let strings = symbolStrings {
            stringTable.append(0)
            for s in strings { stringTable.append(contentsOf: Array(s.utf8)); stringTable.append(0) }
        }

        // Pre-compute sizeofcmds so section file offsets can point past the LC region.
        var ncmds = segments.count
        if uuid != nil { ncmds += 1 }
        if cryptId != nil { ncmds += 1 }
        if codeSignature { ncmds += 1 }
        if symbolStrings != nil { ncmds += 1 }
        var sizeofcmds = 0
        for seg in segments { sizeofcmds += 72 + seg.sections.count * 80 }
        if uuid != nil { sizeofcmds += 24 }
        if cryptId != nil { sizeofcmds += 24 }
        if codeSignature { sizeofcmds += 16 }   // linkedit_data_command
        if symbolStrings != nil { sizeofcmds += 24 } // symtab_command

        let headerSize = 32
        var dataArea: [UInt8] = []
        var nextOffset = headerSize + sizeofcmds

        for seg in segments {
            var lc = [UInt8]()
            append32(&lc, 0x19) // LC_SEGMENT_64
            append32(&lc, UInt32(72 + seg.sections.count * 80))
            appendFixed(&lc, seg.name, 16)
            append64(&lc, 0) // vmaddr
            append64(&lc, 0) // vmsize
            append64(&lc, 0) // fileoff
            append64(&lc, 0) // filesize
            append32(&lc, 7) // maxprot
            append32(&lc, 5) // initprot
            append32(&lc, UInt32(seg.sections.count))
            append32(&lc, 0) // flags
            for section in seg.sections {
                switch section {
                case .data(let sect, let segName, let bytes):
                    appendSection(&lc, sect: sect, seg: segName, size: bytes.count, offset: nextOffset, flags: 0)
                    dataArea.append(contentsOf: bytes)
                    nextOffset += bytes.count
                case .zerofill(let sect, let segName, let size):
                    appendSection(&lc, sect: sect, seg: segName, size: size, offset: 0, flags: 1) // S_ZEROFILL
                }
            }
            loadCommands.append(lc)
        }

        if let uuid = uuid {
            var lc = [UInt8]()
            append32(&lc, 0x1b) // LC_UUID
            append32(&lc, 24)
            lc.append(contentsOf: uuid)
            loadCommands.append(lc)
        }
        if let cryptId = cryptId {
            var lc = [UInt8]()
            append32(&lc, 0x2c) // LC_ENCRYPTION_INFO_64
            append32(&lc, 24)
            append32(&lc, 0) // cryptoff
            append32(&lc, 0) // cryptsize
            append32(&lc, cryptId)
            append32(&lc, 0) // pad
            loadCommands.append(lc)
        }
        if codeSignature {
            var lc = [UInt8]()
            append32(&lc, 0x1d) // LC_CODE_SIGNATURE
            append32(&lc, 16)
            append32(&lc, 0) // dataoff
            append32(&lc, 0) // datasize
            loadCommands.append(lc)
        }
        if symbolStrings != nil {
            // String table is laid out right after the section data.
            let stroff = nextOffset
            dataArea.append(contentsOf: stringTable)
            nextOffset += stringTable.count
            var lc = [UInt8]()
            append32(&lc, 0x2) // LC_SYMTAB
            append32(&lc, 24)
            append32(&lc, 0) // symoff
            append32(&lc, 0) // nsyms
            append32(&lc, UInt32(stroff)) // stroff
            append32(&lc, UInt32(stringTable.count)) // strsize
            loadCommands.append(lc)
        }

        commandCount = ncmds
        commandsSize = sizeofcmds

        var out = [UInt8]()
        append32(&out, 0xfeed_facf) // MH_MAGIC_64 (little-endian on disk)
        append32(&out, UInt32(bitPattern: cpuType))
        append32(&out, 0) // cpusubtype
        append32(&out, fileType)
        append32(&out, UInt32(ncmds))
        append32(&out, UInt32(sizeofcmds))
        append32(&out, (pie ? 0x20_0000 : 0) | extraFlags) // MH_PIE | extra mitigation flags
        append32(&out, 0) // reserved
        for lc in loadCommands { out.append(contentsOf: lc) }
        out.append(contentsOf: dataArea)
        return Data(out)
    }

    static func fat(_ slices: [Data]) -> Data {
        var out = [UInt8]()
        func be32(_ v: UInt32) { out.append(UInt8((v >> 24) & 0xff)); out.append(UInt8((v >> 16) & 0xff)); out.append(UInt8((v >> 8) & 0xff)); out.append(UInt8(v & 0xff)) }
        be32(0xcafe_babe) // FAT_MAGIC (big-endian on disk)
        be32(UInt32(slices.count))

        let headerSize = 8 + slices.count * 20
        var offset = align(headerSize, 0x4000)
        var entries: [(off: Int, size: Int)] = []
        for slice in slices {
            entries.append((offset, slice.count))
            offset = align(offset + slice.count, 0x4000)
        }
        for (i, slice) in slices.enumerated() {
            // cputype/cpusubtype are not used by the inspector; offset/size are.
            be32(UInt32(bitPattern: i == 0 ? 0x0100_000c : 0x0100_0007))
            be32(0)
            be32(UInt32(entries[i].off))
            be32(UInt32(entries[i].size))
            be32(14) // align (2^14)
        }
        // Pad to first slice offset, then lay out slices on their aligned offsets.
        while out.count < entries[0].off { out.append(0) }
        for (i, slice) in slices.enumerated() {
            while out.count < entries[i].off { out.append(0) }
            out.append(contentsOf: [UInt8](slice))
        }
        return Data(out)
    }

    private var cpuType: Int32 { arch == .arm64 ? (12 | 0x0100_0000) : (7 | 0x0100_0000) }

    private func appendSection(_ lc: inout [UInt8], sect: String, seg: String, size: Int, offset: Int, flags: UInt32) {
        appendFixed(&lc, sect, 16)
        appendFixed(&lc, seg, 16)
        append64(&lc, 0) // addr
        append64(&lc, UInt64(size))
        append32(&lc, UInt32(offset))
        append32(&lc, 0) // align
        append32(&lc, 0) // reloff
        append32(&lc, 0) // nreloc
        append32(&lc, flags)
        append32(&lc, 0) // reserved1
        append32(&lc, 0) // reserved2
        append32(&lc, 0) // reserved3
    }

    private func append32(_ a: inout [UInt8], _ v: UInt32) {
        a.append(UInt8(v & 0xff)); a.append(UInt8((v >> 8) & 0xff)); a.append(UInt8((v >> 16) & 0xff)); a.append(UInt8((v >> 24) & 0xff))
    }
    private func append64(_ a: inout [UInt8], _ v: UInt64) {
        for shift in stride(from: 0, through: 56, by: 8) { a.append(UInt8((v >> UInt64(shift)) & 0xff)) }
    }
    private func appendFixed(_ a: inout [UInt8], _ s: String, _ len: Int) {
        var bytes = Array(s.utf8)
        if bytes.count > len { bytes = Array(bytes.prefix(len)) }
        a.append(contentsOf: bytes)
        a.append(contentsOf: [UInt8](repeating: 0, count: len - bytes.count))
    }
}

private func align(_ n: Int, _ to: Int) -> Int { (n + to - 1) / to * to }
