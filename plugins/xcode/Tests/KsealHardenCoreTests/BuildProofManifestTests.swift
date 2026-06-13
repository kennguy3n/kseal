import XCTest
@testable import KsealHardenCore

final class BuildProofManifestTests: XCTestCase {
    private func sample() -> BuildProofManifest {
        BuildProofManifest(
            sdkVersion: "0.1.0",
            buildHash: "deadbeef",
            versionName: "1.2.3",
            versionCode: 123,
            protectionProfileId: "profile-1",
            polymorphism: .init(seedDigest: "abc123"),
            toolVersions: ["swift": "5.10.1", "strip": "2.38"],
            transforms: [
                .init(kind: "string-obfuscation", algorithm: "seed-xor/sha256-ctr", count: 3),
                .init(kind: "symbol-strip", algorithm: "strip", count: 42, detail: ["flags": "-x"]),
            ],
            modules: ["string-hardening", "polymorphism", "build-proof"],
            provenance: .init(generatedAt: "2026-06-13T03:00:00Z", generator: "kseal-harden/0.1.0", host: "swiftpm-build-plugin")
        )
    }

    func testRoundTrip() throws {
        let manifest = sample()
        let data = try manifest.jsonData()
        let decoded = try BuildProofManifest.decode(from: data)
        XCTAssertEqual(decoded, manifest)
    }

    func testRequiredFieldsPresent() throws {
        let json = try sample().jsonString()
        for field in ["schemaVersion", "platform", "sdkVersion", "buildHash",
                      "versionName", "versionCode", "seedDigest", "toolVersions",
                      "transforms", "modules", "provenance"] {
            XCTAssertTrue(json.contains("\"\(field)\""), "manifest JSON missing \(field)")
        }
        XCTAssertTrue(json.contains("\"1.0\""), "schema version should be 1.0")
    }

    func testDeterministicSortedKeys() throws {
        let a = try sample().jsonString()
        let b = try sample().jsonString()
        XCTAssertEqual(a, b)
        // Sorted keys: platform precedes sdkVersion precedes schemaVersion? check ordering of a couple keys
        let platformIdx = a.range(of: "\"platform\"")!.lowerBound
        let sdkIdx = a.range(of: "\"sdkVersion\"")!.lowerBound
        XCTAssertLessThan(platformIdx, sdkIdx)
    }

    func testSlashesNotEscaped() throws {
        var manifest = sample()
        manifest.transforms[0].detail = ["url": "https://example.com/path"]
        let json = try manifest.jsonString()
        XCTAssertTrue(json.contains("https://example.com/path"))
        XCTAssertFalse(json.contains("https:\\/\\/"))
    }

    // MARK: build-proof v2 (additive within schema 1.0)

    func testManifestRevisionDefaultsToCurrent() throws {
        XCTAssertEqual(sample().manifestRevision, BuildProofManifest.currentManifestRevision)
        XCTAssertTrue(try sample().jsonString().contains("\"manifestRevision\""))
        // Schema version is unchanged — additive, not breaking.
        XCTAssertTrue(try sample().jsonString().contains("\"1.0\""))
    }

    func testReproducibilityAndHashCoverageRoundTrip() throws {
        var manifest = sample()
        manifest.reproducibility = .init(reproducible: true, seedDerivation: "explicit")
        manifest.hashCoverage = .init(
            sliceCount: 1, sectionCount: 2, bytesCovered: 128,
            artifactsRoot: "abc", complete: true
        )
        let decoded = try BuildProofManifest.decode(from: try manifest.jsonData())
        XCTAssertEqual(decoded, manifest)
        XCTAssertEqual(decoded.reproducibility?.reproducible, true)
        XCTAssertEqual(decoded.hashCoverage?.bytesCovered, 128)
    }

    func testRevision1ManifestDecodesWithoutV2Fields() throws {
        // A manifest written before revision 2 has none of the v2 keys; it must
        // still decode (backward compatibility), leaving them nil.
        let legacy = """
        {"buildHash":"h","modules":[],"platform":"ios","protectionProfileId":"",
         "polymorphism":{"seedDigest":"00","algorithm":"sha256-ctr"},
         "provenance":{"generatedAt":"t","generator":"g","host":"h"},
         "schemaVersion":"1.0","sdkVersion":"0.1.0","toolVersions":{},
         "transforms":[],"versionCode":1,"versionName":"1.0"}
        """
        let decoded = try BuildProofManifest.decode(from: Data(legacy.utf8))
        XCTAssertNil(decoded.manifestRevision)
        XCTAssertNil(decoded.reproducibility)
        XCTAssertNil(decoded.hashCoverage)
        XCTAssertNil(decoded.posture)
        XCTAssertEqual(decoded.buildHash, "h")
    }

    func testHashCoverageDerivedFromIntegrityIsIndependentlyVerifiable() throws {
        let slice = BuildProofManifest.Integrity.Slice(
            arch: "arm64", fileType: "execute", pie: true, encrypted: false, uuid: "",
            loadCommandCount: 2, loadCommandsSize: 100, loadCommandsHash: "lc",
            sections: [
                .init(segment: "__TEXT", section: "__text", size: 10, hash: "aa"),
                .init(segment: "__DATA", section: "__bss", size: 4096, hash: ""), // zero-fill
            ]
        )
        let integrity = BuildProofManifest.Integrity(slices: [slice])
        let coverage = BuildProofManifest.HashCoverage.from(integrity: integrity)

        XCTAssertEqual(coverage.sliceCount, 1)
        XCTAssertEqual(coverage.sectionCount, 2)
        XCTAssertEqual(coverage.bytesCovered, 10, "zero-fill section contributes no covered bytes")
        XCTAssertTrue(coverage.complete)

        // Recompute the root the same way a verifier would.
        let expected = SHA256.hexDigest(Array([
            "arm64\u{1f}__loadcommands\u{1f}\u{1f}lc",
            "arm64\u{1f}__TEXT\u{1f}__text\u{1f}aa",
        ].joined(separator: "\n").utf8))
        XCTAssertEqual(coverage.artifactsRoot, expected)
    }
}
