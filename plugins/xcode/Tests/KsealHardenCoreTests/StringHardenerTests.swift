import XCTest
@testable import KsealHardenCore

final class StringHardenerTests: XCTestCase {
    private let seed = PolymorphismSeed(bytes: Array(repeating: 0x5a, count: 32))

    func testRoundTrip() {
        let hardener = StringHardener()
        let entries = ["apiBaseURL": "https://api.example.com", "telemetryKey": "k-123-456"]
        let hardened = hardener.harden(entries: entries, seed: seed)
        XCTAssertEqual(hardened.count, 2)
        for h in hardened {
            XCTAssertEqual(hardener.reveal(h), entries[h.identifier])
        }
    }

    func testPlaintextAbsentFromCiphertext() {
        let hardener = StringHardener()
        let secret = "SuperSecretToken"
        let hardened = hardener.harden(entries: ["token": secret], seed: seed)[0]
        let cipherString = String(decoding: hardened.ciphertext, as: UTF8.self)
        XCTAssertFalse(cipherString.contains(secret))
        XCTAssertNotEqual(hardened.ciphertext, Array(secret.utf8))
    }

    func testGeneratedSourceHidesPlaintextAndCompilesStructurally() {
        let hardener = StringHardener()
        let secret = "https://secret.example.com/v1"
        let source = hardener.generateSwiftSource(hardener.harden(entries: ["endpoint": secret], seed: seed))
        XCTAssertFalse(source.contains(secret), "plaintext must not appear in generated source")
        XCTAssertTrue(source.contains("enum KsealSecureStrings"))
        XCTAssertTrue(source.contains("static var endpoint: String"))
        XCTAssertTrue(source.contains("func reveal("))
    }

    func testDeterministicForSameSeed() {
        let hardener = StringHardener()
        let a = hardener.harden(entries: ["x": "value"], seed: seed)
        let b = hardener.harden(entries: ["x": "value"], seed: seed)
        XCTAssertEqual(a, b)
    }

    func testDiffersAcrossSeeds() {
        let hardener = StringHardener()
        let other = PolymorphismSeed(bytes: Array(repeating: 0x01, count: 32))
        let a = hardener.harden(entries: ["x": "value"], seed: seed)[0]
        let b = hardener.harden(entries: ["x": "value"], seed: other)[0]
        XCTAssertNotEqual(a.ciphertext, b.ciphertext, "polymorphism: different builds differ")
    }

    func testIdentifierSanitization() {
        XCTAssertEqual(StringHardener.sanitizeIdentifier("api.base-url"), "api_base_url")
        XCTAssertEqual(StringHardener.sanitizeIdentifier("123key"), "_123key")
        XCTAssertEqual(StringHardener.sanitizeIdentifier(""), "_")
    }

    func testKeywordIdentifiersAreBacktickEscaped() {
        let hardener = StringHardener()
        let source = hardener.generateSwiftSource(
            hardener.harden(entries: ["class": "a", "return": "b", "normal": "c"], seed: seed)
        )
        XCTAssertTrue(source.contains("static var `class`: String"))
        XCTAssertTrue(source.contains("static var `return`: String"))
        XCTAssertTrue(source.contains("static var normal: String"))
    }

    func testCollidingIdentifiersAreDisambiguated() {
        let hardener = StringHardener()
        // "api.url" and "api-url" both sanitize to "api_url".
        let source = hardener.generateSwiftSource(
            hardener.harden(entries: ["api.url": "x", "api-url": "y"], seed: seed)
        )
        XCTAssertTrue(source.contains("static var api_url: String"))
        XCTAssertTrue(source.contains("static var api_url_2: String"))
    }

    func testUnicodeRoundTrip() {
        let hardener = StringHardener()
        let value = "café—naïve—日本語"
        let hardened = hardener.harden(entries: ["u": value], seed: seed)[0]
        XCTAssertEqual(hardener.reveal(hardened), value)
    }
}
