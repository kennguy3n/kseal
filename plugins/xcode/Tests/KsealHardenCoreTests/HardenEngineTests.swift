import XCTest
@testable import KsealHardenCore

final class HardenEngineTests: XCTestCase {
    private let fixedClock: () -> Date = { Date(timeIntervalSince1970: 1_700_000_000) }
    private let seed = PolymorphismSeed(bytes: Array(repeating: 0x33, count: 32))

    private func request() -> HardenRequest {
        HardenRequest(
            targetName: "DemoApp",
            sdkVersion: "0.1.0",
            versionName: "2.0.0",
            versionCode: 42,
            protectionProfileId: "profile-x",
            secureStrings: ["apiBaseURL": "https://api.example.com", "key": "abc"],
            extraToolVersions: ["swift": "5.10.1"]
        )
    }

    func testManifestPopulatedWithExpectedFields() throws {
        let output = try HardenEngine(clock: fixedClock).run(request(), seed: seed)
        let m = output.manifest
        XCTAssertEqual(m.schemaVersion, "1.0")
        XCTAssertEqual(m.platform, "ios")
        XCTAssertEqual(m.sdkVersion, "0.1.0")
        XCTAssertEqual(m.versionName, "2.0.0")
        XCTAssertEqual(m.versionCode, 42)
        XCTAssertEqual(m.protectionProfileId, "profile-x")
        XCTAssertEqual(m.polymorphism.seedDigest, seed.digestHex)
        XCTAssertEqual(m.toolVersions["swift"], "5.10.1")
        XCTAssertEqual(m.toolVersions["ksealHarden"], ksealHardenVersion)
        XCTAssertFalse(m.buildHash.isEmpty)
        XCTAssertEqual(m.buildHash.count, 64) // sha256 hex
        XCTAssertTrue(m.modules.contains("string-hardening"))
        XCTAssertEqual(m.provenance.generatedAt, "2023-11-14T22:13:20Z")
    }

    func testTransformRecordsStringCount() throws {
        let output = try HardenEngine(clock: fixedClock).run(request(), seed: seed)
        let stringTransform = try XCTUnwrap(output.manifest.transforms.first { $0.kind == "string-obfuscation" })
        XCTAssertEqual(stringTransform.count, 2)
    }

    func testGeneratedSourceHidesPlaintext() throws {
        let output = try HardenEngine(clock: fixedClock).run(request(), seed: seed)
        XCTAssertFalse(output.generatedSwiftSource.contains("https://api.example.com"))
        XCTAssertTrue(output.generatedSwiftSource.contains("static var apiBaseURL"))
    }

    func testBuildHashDeterministicGivenSeed() throws {
        let a = try HardenEngine(clock: fixedClock).run(request(), seed: seed)
        let b = try HardenEngine(clock: fixedClock).run(request(), seed: seed)
        XCTAssertEqual(a.manifest.buildHash, b.manifest.buildHash)
    }

    func testBuildHashChangesWithSeed() throws {
        let other = PolymorphismSeed(bytes: Array(repeating: 0x99, count: 32))
        let a = try HardenEngine(clock: fixedClock).run(request(), seed: seed)
        let b = try HardenEngine(clock: fixedClock).run(request(), seed: other)
        XCTAssertNotEqual(a.manifest.buildHash, b.manifest.buildHash)
    }

    func testBuildHashChangesWithVersion() throws {
        var req2 = request()
        req2.versionCode = 43
        let a = try HardenEngine(clock: fixedClock).run(request(), seed: seed)
        let b = try HardenEngine(clock: fixedClock).run(req2, seed: seed)
        XCTAssertNotEqual(a.manifest.buildHash, b.manifest.buildHash)
    }

    func testEmptySecureStrings() throws {
        var req = request()
        req.secureStrings = [:]
        let output = try HardenEngine(clock: fixedClock).run(req, seed: seed)
        XCTAssertEqual(output.manifest.transforms.first?.count, 0)
        XCTAssertTrue(output.generatedSwiftSource.contains("enum KsealSecureStrings"))
    }

    func testManifestSerializesToValidJSON() throws {
        let output = try HardenEngine(clock: fixedClock).run(request(), seed: seed)
        let json = try output.manifest.jsonString()
        XCTAssertNoThrow(try JSONSerialization.jsonObject(with: Data(json.utf8)))
    }
}
