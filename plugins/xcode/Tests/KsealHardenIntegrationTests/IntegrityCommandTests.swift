import XCTest
@testable import KsealHardenCore

/// End-to-end coverage of the `kseal-harden integrity` subcommand: it must read
/// an emitted manifest, compute Mach-O section-hash integrity from a *real*
/// linked binary, and bake the evidence back into the manifest (adding the
/// `macho-section-integrity` transform/module) without touching the build hash.
///
/// Skips cleanly when neither the built CLI nor a Mach-O binary is reachable on
/// the host (e.g. a non-Apple CI image with no sample binaries), rather than
/// faking a pass.
final class IntegrityCommandTests: XCTestCase {

    private var packageRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    func testIntegrityCommandBakesEvidenceIntoManifest() throws {
        let cli = try locateCLI()

        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("kseal-integrity-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: scratch) }

        // A deterministic, host-independent thin arm64 Mach-O to harden.
        let machO = scratch.appendingPathComponent("fixture.macho")
        try Data(syntheticArm64MachO()).write(to: machO)

        // A pre-existing manifest as produced by `generate`.
        let manifest = BuildProofManifest(
            sdkVersion: "0.1.0", buildHash: String(repeating: "a", count: 64),
            versionName: "1.0", versionCode: 1,
            polymorphism: .init(seedDigest: String(repeating: "0", count: 64)),
            toolVersions: [:], transforms: [], modules: ["string-hardening"],
            provenance: .init(generatedAt: "t", generator: "kseal-harden", host: "test")
        )
        let manifestURL = scratch.appendingPathComponent("manifest.json")
        try manifest.jsonData().write(to: manifestURL)
        let outURL = scratch.appendingPathComponent("manifest.integrity.json")

        let result = try run(cli, [
            "integrity",
            "--binary", machO.path,
            "--manifest", manifestURL.path,
            "--out-manifest", outURL.path,
        ])
        XCTAssertEqual(result.exitCode, 0, "integrity command failed: \(result.standardError)")

        let baked = try BuildProofManifest.decode(from: Data(contentsOf: outURL))
        let integrity = try XCTUnwrap(baked.integrity, "manifest must carry integrity evidence")
        XCTAssertEqual(integrity.format, "macho")
        XCTAssertFalse(integrity.slices.isEmpty)
        // Every non-zero-fill section must carry a 64-hex SHA-256.
        for slice in integrity.slices {
            XCTAssertFalse(slice.loadCommandsHash.isEmpty)
            for section in slice.sections where !section.hash.isEmpty {
                XCTAssertEqual(section.hash.count, 64)
            }
        }

        let transform = try XCTUnwrap(baked.transforms.first { $0.kind == "macho-section-integrity" })
        XCTAssertEqual(transform.algorithm, "sha256")
        XCTAssertTrue(baked.modules.contains("macho-section-integrity"))
        // Existing fields are preserved; the build hash is not recomputed here.
        XCTAssertEqual(baked.buildHash, manifest.buildHash)
        XCTAssertTrue(baked.modules.contains("string-hardening"))

        // The same post-link pass bakes the per-binary posture and a hash-coverage
        // summary, and lifts the manifest to the current revision.
        let posture = try XCTUnwrap(baked.posture, "manifest must carry posture")
        XCTAssertFalse(posture.slices.isEmpty)
        XCTAssertTrue(baked.modules.contains("macho-binary-posture"))
        XCTAssertNotNil(baked.transforms.first { $0.kind == "macho-binary-posture" })
        let coverage = try XCTUnwrap(baked.hashCoverage, "manifest must carry hash coverage")
        XCTAssertEqual(coverage.sliceCount, integrity.slices.count)
        XCTAssertEqual(coverage.artifactsRoot, BuildProofManifest.HashCoverage.from(integrity: integrity).artifactsRoot)
        XCTAssertEqual(baked.manifestRevision, BuildProofManifest.currentManifestRevision)

        // Re-running must be idempotent (no duplicate transforms).
        let second = try run(cli, ["integrity", "--binary", machO.path, "--manifest", outURL.path])
        XCTAssertEqual(second.exitCode, 0)
        let reBaked = try BuildProofManifest.decode(from: Data(contentsOf: outURL))
        XCTAssertEqual(reBaked.transforms.filter { $0.kind == "macho-section-integrity" }.count, 1)
        XCTAssertEqual(reBaked.transforms.filter { $0.kind == "macho-binary-posture" }.count, 1)
    }

    // MARK: - helpers

    private func locateCLI() throws -> URL {
        let buildDir = packageRoot.appendingPathComponent(".build")
        guard let enumerator = FileManager.default.enumerator(at: buildDir, includingPropertiesForKeys: nil) else {
            throw XCTSkip("no .build directory; CLI not built")
        }
        for case let url as URL in enumerator where url.lastPathComponent == "kseal-harden" {
            if FileManager.default.isExecutableFile(atPath: url.path) { return url }
        }
        throw XCTSkip("kseal-harden CLI not found under .build")
    }

    /// A minimal but valid little-endian thin arm64 Mach-O dylib: one
    /// `LC_SEGMENT_64` (`__TEXT`) with a `__text` data section plus a `__bss`
    /// zero-fill section, and an `LC_UUID`. Enough for the inspector to produce
    /// real section + load-command hashes.
    private func syntheticArm64MachO() -> [UInt8] {
        func le32(_ v: UInt32) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 24) & 0xff)] }
        func le64(_ v: UInt64) -> [UInt8] { (0...7).map { UInt8((v >> UInt64($0 * 8)) & 0xff) } }
        func name16(_ s: String) -> [UInt8] { var b = Array(s.utf8); b += [UInt8](repeating: 0, count: 16 - b.count); return b }

        let text = Array("synthetic-arm64-text".utf8)
        let segHeader = 72, sect = 80
        let sizeofcmds = (segHeader + 2 * sect) + 24 // 1 segment (2 sections) + LC_UUID
        let textOffset = 32 + sizeofcmds

        var seg = le32(0x19) + le32(UInt32(segHeader + 2 * sect)) + name16("__TEXT")
        seg += le64(0) + le64(0) + le64(0) + le64(0) // vmaddr/vmsize/fileoff/filesize
        seg += le32(7) + le32(5) + le32(2) + le32(0) // maxprot/initprot/nsects/flags
        // __text (data) section
        seg += name16("__text") + name16("__TEXT") + le64(0) + le64(UInt64(text.count))
        seg += le32(UInt32(textOffset)) + le32(0) + le32(0) + le32(0) + le32(0) + le32(0) + le32(0) + le32(0)
        // __bss (zero-fill) section
        seg += name16("__bss") + name16("__DATA") + le64(0) + le64(1024)
        seg += le32(0) + le32(0) + le32(0) + le32(0) + le32(1) + le32(0) + le32(0) + le32(0) // S_ZEROFILL

        let uuid = le32(0x1b) + le32(24) + [UInt8](repeating: 0x7c, count: 16)

        var out = le32(0xfeed_facf) // MH_MAGIC_64
        out += le32(UInt32(bitPattern: 12 | 0x0100_0000)) // CPU_TYPE_ARM64
        out += le32(0) + le32(6) + le32(2) + le32(UInt32(sizeofcmds)) + le32(0x20_0000) + le32(0) // dylib, MH_PIE
        out += seg + uuid + text
        return out
    }

    private func run(_ executable: URL, _ arguments: [String]) throws -> ProcessResult {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        let outPipe = Pipe(); let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        try process.run()
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return ProcessResult(
            exitCode: process.terminationStatus,
            standardOutput: String(decoding: outData, as: UTF8.self),
            standardError: String(decoding: errData, as: UTF8.self)
        )
    }
}
