import XCTest
@testable import KsealHardenCore

final class PolymorphismSeedTests: XCTestCase {
    func testRandomSeedsDiffer() {
        let a = PolymorphismSeed.random()
        let b = PolymorphismSeed.random()
        XCTAssertEqual(a.bytes.count, 32)
        XCTAssertNotEqual(a.bytes, b.bytes, "two random seeds should not collide")
    }

    func testHexRoundTrip() {
        let seed = PolymorphismSeed.random()
        let restored = PolymorphismSeed(hex: seed.hex)
        XCTAssertEqual(restored?.bytes, seed.bytes)
    }

    func testRejectsShortSeed() {
        XCTAssertNil(PolymorphismSeed(hex: "00112233")) // < 16 bytes
    }

    func testResolvePrefersEnvironment() {
        let hex = String(repeating: "ab", count: 32)
        let seed = PolymorphismSeed.resolve(environment: ["KSEAL_BUILD_SEED": hex])
        XCTAssertEqual(seed.hex, hex)
    }

    func testResolveFallsBackToRandom() {
        let seed = PolymorphismSeed.resolve(environment: [:])
        XCTAssertEqual(seed.bytes.count, 32)
    }

    func testDigestIsStableAndNotTheSeed() {
        let seed = PolymorphismSeed(bytes: Array(repeating: 0x42, count: 32))
        XCTAssertEqual(seed.digestHex, SHA256.hexDigest(seed.bytes))
        XCTAssertNotEqual(seed.digestHex, seed.hex)
    }

    func testKeystreamDeterministicAndContextSeparated() {
        let seed = PolymorphismSeed(bytes: Array(repeating: 0x01, count: 32))
        let a1 = seed.keystream(length: 40, context: "ctx-a")
        let a2 = seed.keystream(length: 40, context: "ctx-a")
        let b = seed.keystream(length: 40, context: "ctx-b")
        XCTAssertEqual(a1, a2, "same seed+context must be deterministic")
        XCTAssertNotEqual(a1, b, "different contexts must yield different keystreams")
        XCTAssertEqual(a1.count, 40)
    }

    func testKeystreamCrossesHashBlock() {
        let seed = PolymorphismSeed(bytes: Array(repeating: 0x7e, count: 32))
        let ks = seed.keystream(length: 100, context: "x")
        XCTAssertEqual(ks.count, 100) // > 2 SHA-256 blocks
        XCTAssertEqual(Array(ks.prefix(32)), Array(seed.keystream(length: 32, context: "x")))
    }
}
