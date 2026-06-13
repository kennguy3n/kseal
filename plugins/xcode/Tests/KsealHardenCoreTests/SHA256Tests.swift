import XCTest
@testable import KsealHardenCore

final class SHA256Tests: XCTestCase {
    func testKnownVectors() {
        // FIPS 180-4 / NIST published vectors.
        XCTAssertEqual(SHA256.hexDigest(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(SHA256.hexDigest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(SHA256.hexDigest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    }

    func testLongInputCrossesBlockBoundary() {
        let million = String(repeating: "a", count: 1_000_000)
        XCTAssertEqual(SHA256.hexDigest(million),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }

    func testHexRoundTrip() {
        let bytes: [UInt8] = [0x00, 0x0f, 0xa0, 0xff, 0x10]
        let hex = HexEncoding.encode(bytes)
        XCTAssertEqual(hex, "000fa0ff10")
        XCTAssertEqual(HexEncoding.decode(hex), bytes)
        XCTAssertNil(HexEncoding.decode("xyz"))
        XCTAssertNil(HexEncoding.decode("abc")) // odd length
    }
}
