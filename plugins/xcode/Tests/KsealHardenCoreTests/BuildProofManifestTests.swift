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
}
