import XCTest
@testable import KsealDesktop

/// Exercises the secure-update verification against the **real** Ed25519
/// verifier in the Rust core over the C ABI, using fixed test vectors signed by
/// a known Ed25519 key (the external feed is the only mocked surface).
final class SecureUpdateTests: XCTestCase {

    // Ed25519 public key (32 raw bytes) matching the signatures below.
    private let publicKey = Data([
        60, 237, 247, 255, 72, 221, 244, 209, 215, 7, 12, 78, 108, 106, 164, 173,
        35, 191, 29, 238, 148, 173, 81, 111, 122, 123, 212, 211, 227, 211, 34, 244,
    ])

    private let archive2 = Data("kseal-update-archive-v2.0.0-payload".utf8)               // len 35
    private let archive3 = Data("kseal-update-archive-v3.0.0-payload-bigger".utf8)        // len 42
    private let sig2 = "d0e4iyWmsU8YBw+xumDMA7E18h1IdiY4up3F211Va6XXINVNVDlZrZxwPh8fSKrSM3uv6KitoRY/SrMf3/LxDA=="
    private let sig3 = "7K34Kguf2PymzBV4hOOgiMuTPqVbg4orirvI2f/qmP10FSa4JJNGWOB+/EvTuSFMOPgMnFX0IO2lN8yQow5BAA=="

    private let url2 = "https://updates.example/app-2.0.0.zip"
    private let url3 = "https://updates.example/app-3.0.0.zip"

    private func appcastXML(length2: Int = 35, length3: Int = 42) -> Data {
        Data("""
        <?xml version="1.0" encoding="utf-8"?>
        <rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
          <channel>
            <title>kseal</title>
            <item>
              <sparkle:version>2.0.0</sparkle:version>
              <enclosure url="\(url2)" length="\(length2)" type="application/octet-stream"
                         sparkle:edSignature="\(sig2)"/>
            </item>
            <item>
              <sparkle:version>3.0.0</sparkle:version>
              <sparkle:minimumSystemVersion>12.0</sparkle:minimumSystemVersion>
              <enclosure url="\(url3)" length="\(length3)" type="application/octet-stream"
                         sparkle:edSignature="\(sig3)"/>
            </item>
          </channel>
        </rss>
        """.utf8)
    }

    private func feed(length2: Int = 35, length3: Int = 42, tamper: Bool = false) throws -> InMemoryAppcastFeed {
        let a3 = tamper ? Data("tampered-archive-bytes-tampered-archive-by".utf8) : archive3
        return try InMemoryAppcastFeed(
            appcastXML: appcastXML(length2: length2, length3: length3),
            archives: [url2: archive2, url3: a3])
    }

    private func policy(current: String, system: String? = "13.0", requireNotarization: Bool = false) -> UpdateChannelPolicy {
        UpdateChannelPolicy(
            publicKey: publicKey,
            currentVersion: SemanticVersion(current),
            currentSystemVersion: system.map(SemanticVersion.init),
            requireNotarization: requireNotarization)
    }

    // MARK: - SemanticVersion

    func testVersionOrdering() {
        XCTAssertTrue(SemanticVersion("1.10.0") > SemanticVersion("1.9.0"))
        XCTAssertTrue(SemanticVersion("2.0") == SemanticVersion("2.0.0"))
        XCTAssertTrue(SemanticVersion("3.0.1") > SemanticVersion("3.0.0"))
        XCTAssertFalse(SemanticVersion("1.0.0") > SemanticVersion("1.0.0"))
    }

    // MARK: - Parsing

    func testParsesAllWellFormedItems() throws {
        let appcast = try AppcastParser.parse(appcastXML())
        XCTAssertEqual(appcast.items.count, 2)
        XCTAssertEqual(appcast.items[1].version, SemanticVersion("3.0.0"))
        XCTAssertEqual(appcast.items[1].minimumSystemVersion, SemanticVersion("12.0"))
        XCTAssertEqual(appcast.items[0].contentLength, 35)
    }

    func testMalformedFeedThrows() {
        XCTAssertThrowsError(try AppcastParser.parse(Data("<rss><channel><item".utf8))) {
            XCTAssertEqual($0 as? SecureUpdateError, .malformedFeed)
        }
    }

    func testItemMissingSignatureIsSkipped() throws {
        let xml = Data("""
        <rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel>
        <item><sparkle:version>9.0.0</sparkle:version>
        <enclosure url="u" length="10" type="application/octet-stream"/></item>
        </channel></rss>
        """.utf8)
        XCTAssertTrue(try AppcastParser.parse(xml).items.isEmpty)
    }

    // MARK: - Verification (real Ed25519 via FFI)

    func testSelectsNewestAndVerifiesValidSignature() throws {
        let channel = SecureUpdateChannel(policy: policy(current: "1.0.0"), feed: try feed())
        guard case .updateAvailable(let update) = try channel.checkForUpdate() else {
            return XCTFail("expected an update")
        }
        XCTAssertEqual(update.item.version, SemanticVersion("3.0.0"))
        XCTAssertEqual(update.archive, archive3)
    }

    func testMinimumSystemVersionGatesNewerItem() throws {
        // OS too old for v3 → falls back to verifying v2 (no OS gate).
        let channel = SecureUpdateChannel(policy: policy(current: "1.0.0", system: "11.0"), feed: try feed())
        guard case .updateAvailable(let update) = try channel.checkForUpdate() else {
            return XCTFail("expected v2")
        }
        XCTAssertEqual(update.item.version, SemanticVersion("2.0.0"))
    }

    func testUpToDateWhenCurrentIsNewest() throws {
        let channel = SecureUpdateChannel(policy: policy(current: "3.0.0"), feed: try feed())
        XCTAssertEqual(try channel.checkForUpdate(), .upToDate)
    }

    func testTamperedArchiveFailsClosed() throws {
        let channel = SecureUpdateChannel(policy: policy(current: "1.0.0"), feed: try feed(tamper: true))
        XCTAssertThrowsError(try channel.checkForUpdate()) {
            XCTAssertEqual($0 as? SecureUpdateError, .signatureInvalid)
        }
    }

    func testLengthMismatchFailsClosed() throws {
        // Declared length for v3 disagrees with the actual archive bytes.
        let channel = SecureUpdateChannel(policy: policy(current: "1.0.0"), feed: try feed(length3: 999))
        XCTAssertThrowsError(try channel.checkForUpdate()) {
            guard case .lengthMismatch = ($0 as? SecureUpdateError) else {
                return XCTFail("expected lengthMismatch, got \($0)")
            }
        }
    }

    func testNotarizationRequiredAndMissingFailsClosed() throws {
        struct DenyNotary: UpdateNotaryVerifier {
            func isNotarized(archive: Data, item: AppcastItem) -> Bool { false }
        }
        let channel = SecureUpdateChannel(
            policy: policy(current: "1.0.0", requireNotarization: true),
            feed: try feed(), notary: DenyNotary())
        XCTAssertThrowsError(try channel.checkForUpdate()) {
            XCTAssertEqual($0 as? SecureUpdateError, .notarizationFailed)
        }
    }

    func testNotarizationRequiredAndPresentSucceeds() throws {
        let channel = SecureUpdateChannel(
            policy: policy(current: "1.0.0", requireNotarization: true),
            feed: try feed(), notary: PermissiveNotaryVerifier())
        guard case .updateAvailable = try channel.checkForUpdate() else {
            return XCTFail("expected an update")
        }
    }

    func testInvalidChannelKeyFailsClosed() throws {
        let badPolicy = UpdateChannelPolicy(
            publicKey: Data(repeating: 0, count: 16), currentVersion: SemanticVersion("1.0.0"))
        let channel = SecureUpdateChannel(policy: badPolicy, feed: try feed())
        XCTAssertThrowsError(try channel.checkForUpdate()) {
            XCTAssertEqual($0 as? SecureUpdateError, .invalidChannelKey)
        }
    }

    func testWrongChannelKeyRejectsValidlySignedArchive() throws {
        // A 32-byte but wrong key must not verify the signature → fail closed.
        let wrong = UpdateChannelPolicy(
            publicKey: Data(repeating: 9, count: 32), currentVersion: SemanticVersion("1.0.0"))
        let channel = SecureUpdateChannel(policy: wrong, feed: try feed())
        XCTAssertThrowsError(try channel.checkForUpdate()) {
            XCTAssertEqual($0 as? SecureUpdateError, .signatureInvalid)
        }
    }
}
