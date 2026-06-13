import XCTest
@testable import KsealDesktop

final class AttestorAndProtoTests: XCTestCase {

    // MARK: - LocalCodeIntegrityAttestor

    func testAttestorEmitsProvenanceForSignedNotarizedBinary() throws {
        let info = CodeSigningInfo(
            isSigned: true, signatureValid: true, teamIdentifier: "ABCDE12345",
            signingIdentifier: "com.example.app", isNotarized: true,
            hardenedRuntimeEnabled: true, cdHashHex: "deadbeef"
        )
        let token = LocalCodeIntegrityAttestor().attestationToken(for: info)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: token) as? [String: String])
        XCTAssertEqual(object["team"], "ABCDE12345")
        XCTAssertEqual(object["cdhash"], "deadbeef")
        XCTAssertEqual(object["id"], "com.example.app")
        XCTAssertEqual(object["notarized"], "1")
    }

    func testAttestorEmitsNothingForUnsignedBinary() {
        let info = CodeSigningInfo(isSigned: false, signatureValid: false)
        XCTAssertTrue(LocalCodeIntegrityAttestor().attestationToken(for: info).isEmpty)
    }

    func testAttestorCarriesNoSecretMaterial() throws {
        // The token must be a bounded, non-PII provenance summary — never the
        // proof key or raw certificate bytes.
        let info = CodeSigningInfo(isSigned: true, signatureValid: true, teamIdentifier: "T", cdHashHex: "ab")
        let token = LocalCodeIntegrityAttestor().attestationToken(for: info)
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: token) as? [String: String])
        XCTAssertEqual(Set(object.keys), ["team", "cdhash", "notarized"])
    }

    // MARK: - RequestProofResultProto

    func testProtoDecodeAllowWithReason() throws {
        let bytes = Data([0x08, 0x01, 0x12, 0x02, 0x4F, 0x4B]) // decision=1, reason="OK"
        let result = try RequestProofResultProto.decode(bytes)
        XCTAssertEqual(result.decision, .allow)
        XCTAssertEqual(result.reason, "OK")
    }

    func testProtoDecodeEmptyIsUnspecified() throws {
        let result = try RequestProofResultProto.decode(Data())
        XCTAssertEqual(result.decision, .unspecified)
        XCTAssertEqual(result.reason, "")
    }

    func testProtoDecodeSkipsUnknownFields() throws {
        // Unknown field 5 (varint) then decision=3 (DENY).
        let bytes = Data([0x28, 0x99, 0x01, 0x08, 0x03])
        let result = try RequestProofResultProto.decode(bytes)
        XCTAssertEqual(result.decision, .deny)
    }

    func testProtoDecodeRejectsTruncatedVarint() {
        XCTAssertThrowsError(try RequestProofResultProto.decode(Data([0x08, 0x80])))
    }

    func testProtoDecodeRejectsOverrunString() {
        // field2 string claims length 5 but only 1 byte follows.
        XCTAssertThrowsError(try RequestProofResultProto.decode(Data([0x12, 0x05, 0x41])))
    }
}
