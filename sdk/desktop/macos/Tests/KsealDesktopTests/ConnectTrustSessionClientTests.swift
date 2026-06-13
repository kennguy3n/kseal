import XCTest
@testable import KsealDesktop

/// A scripted `HTTPTransport` that records requests and returns queued
/// responses, so the Connect JSON/proto wire mapping can be verified with no
/// sockets or server.
private final class RecordingTransport: HTTPTransport {
    struct Call {
        let url: URL
        let headers: [String: String]
        let body: Data
    }

    var responses: [HTTPResponse] = []
    private(set) var calls: [Call] = []

    func post(url: URL, headers: [String: String], body: Data) throws -> HTTPResponse {
        calls.append(Call(url: url, headers: headers, body: body))
        guard !responses.isEmpty else {
            throw TrustSessionError(message: "no scripted response")
        }
        return responses.removeFirst()
    }
}

private func json(_ object: [String: Any]) -> Data {
    try! JSONSerialization.data(withJSONObject: object)
}

final class ConnectTrustSessionClientTests: XCTestCase {

    private func makeClient(_ transport: HTTPTransport) -> ConnectTrustSessionClient {
        ConnectTrustSessionClient(
            config: TrustSessionConfig(
                baseURL: URL(string: "https://edge.kseal.test")!,
                tenantId: "tenant-1",
                appId: "com.example.app"
            ),
            transport: transport
        )
    }

    func testGetNonceParsesBase64AndHitsCorrectPath() throws {
        let transport = RecordingTransport()
        let nonce = Data([1, 2, 3, 4])
        transport.responses = [HTTPResponse(status: 200, body: json(["nonce": nonce.base64EncodedString()]))]

        let result = try makeClient(transport).getNonce()
        XCTAssertEqual(result, nonce)

        let call = try XCTUnwrap(transport.calls.first)
        XCTAssertEqual(call.url.path, "/kseal.v1.TrustService/GetNonce")
        XCTAssertEqual(call.headers["Content-Type"], "application/json")
        XCTAssertEqual(call.headers["Connect-Protocol-Version"], "1")
        let sent = try XCTUnwrap(try JSONSerialization.jsonObject(with: call.body) as? [String: Any])
        XCTAssertEqual(sent["tenantId"] as? String, "tenant-1")
        XCTAssertEqual(sent["platform"] as? String, "PLATFORM_UNSPECIFIED")
    }

    func testGetNonceRejectsEmptyNonce() {
        let transport = RecordingTransport()
        transport.responses = [HTTPResponse(status: 200, body: json(["nonce": ""]))]
        XCTAssertThrowsError(try makeClient(transport).getNonce())
    }

    func testVerifyAttestationEncodesAndDecodes() throws {
        let transport = RecordingTransport()
        transport.responses = [HTTPResponse(status: 200, body: json([
            "trustToken": [
                "tokenId": "tok-42",
                "expiresAt": "1700000999", // int64 as string
                "riskLevel": "TRUST_LEVEL_LOW_RISK",
                "capabilityScope": ["api:read", "api:write"],
            ],
            "signedToken": Data([9, 9, 9]).base64EncodedString(),
            "accepted": true,
        ]))]

        let session = try makeClient(transport).verifyAttestation(
            nonce: Data([5, 6]),
            riskBitset: 0xDEAD_BEEF,
            buildHash: "build-1",
            policyHash: "policy-1",
            instanceId: "inst-1",
            attestationToken: Data([7, 7])
        )

        XCTAssertEqual(session.tokenId, "tok-42")
        XCTAssertTrue(session.accepted)
        XCTAssertEqual(session.expiresAt, 1_700_000_999)
        XCTAssertEqual(session.riskLevel, .lowRisk)
        XCTAssertEqual(session.signedToken, Data([9, 9, 9]))
        XCTAssertEqual(session.capabilityScopes, ["api:read", "api:write"])

        let sent = try XCTUnwrap(try JSONSerialization.jsonObject(with: transport.calls[0].body) as? [String: Any])
        // 64-bit integers must be encoded as strings (proto3 JSON).
        XCTAssertEqual(sent["riskBitset"] as? String, String(UInt64(0xDEAD_BEEF)))
        XCTAssertEqual(sent["nonce"] as? String, Data([5, 6]).base64EncodedString())
        XCTAssertEqual(sent["platformAttestationToken"] as? String, Data([7, 7]).base64EncodedString())
    }

    func testVerifyAttestationDefaultsWhenFieldsOmitted() throws {
        let transport = RecordingTransport()
        // Connect omits zero-valued fields: no `accepted`, no `trustToken`.
        transport.responses = [HTTPResponse(status: 200, body: json(["rejectionReason": "blocked"]))]
        let session = try makeClient(transport).verifyAttestation(
            nonce: Data([1]), riskBitset: 0, buildHash: "", policyHash: "", instanceId: "i", attestationToken: Data()
        )
        XCTAssertFalse(session.accepted)
        XCTAssertEqual(session.rejectionReason, "blocked")
        XCTAssertEqual(session.tokenId, "")
        XCTAssertEqual(session.riskLevel, .unspecified)
    }

    func testVerifyAttestationOmitsEmptyAttestationToken() throws {
        let transport = RecordingTransport()
        transport.responses = [HTTPResponse(status: 200, body: json(["accepted": true, "trustToken": ["tokenId": "t"]]))]
        _ = try makeClient(transport).verifyAttestation(
            nonce: Data([1]), riskBitset: 0, buildHash: "", policyHash: "", instanceId: "i", attestationToken: Data()
        )
        let sent = try XCTUnwrap(try JSONSerialization.jsonObject(with: transport.calls[0].body) as? [String: Any])
        XCTAssertNil(sent["platformAttestationToken"])
    }

    func testServerErrorSurfacesConnectCode() {
        let transport = RecordingTransport()
        transport.responses = [HTTPResponse(status: 400, body: json(["code": "invalid_argument", "message": "bad nonce"]))]
        XCTAssertThrowsError(try makeClient(transport).getNonce()) { error in
            XCTAssertTrue("\(error)".contains("invalid_argument"))
        }
    }

    func testValidateRequestProofForwardsProtoAndDecodesDecision() throws {
        let transport = RecordingTransport()
        // RequestProofResult{ decision: DECISION_STEP_UP(2), reason: "mfa" }
        // field1 varint: tag 0x08, value 2; field2 string: tag 0x12, len 3, "mfa"
        let resultBytes = Data([0x08, 0x02, 0x12, 0x03, 0x6D, 0x66, 0x61])
        transport.responses = [HTTPResponse(status: 200, body: resultBytes)]

        let proof = RequestProof(
            tokenId: "tok", requestHash: Data([1]), nonce: Data([2]),
            sequence: 1, proofBytes: Data([0xAA, 0xBB])
        )
        let decision = try makeClient(transport).validateRequestProof(proof)
        XCTAssertEqual(decision.decision, .stepUp)
        XCTAssertEqual(decision.reason, "mfa")

        let call = try XCTUnwrap(transport.calls.first)
        XCTAssertEqual(call.url.path, "/kseal.v1.TrustService/ValidateRequestProof")
        XCTAssertEqual(call.headers["Content-Type"], "application/proto")
        XCTAssertEqual(call.body, Data([0xAA, 0xBB])) // proof bytes forwarded verbatim
    }
}
