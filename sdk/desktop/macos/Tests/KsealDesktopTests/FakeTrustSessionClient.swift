import Foundation
@testable import KsealDesktop

/// Records inputs and returns canned outputs so the SDK orchestration can be
/// tested without a server.
final class FakeTrustSessionClient: TrustSessionClient {
    var nonce = Data(repeating: 0xAB, count: 16)
    var session = TrustSession(
        tokenId: "tok", signedToken: Data(), accepted: true,
        rejectionReason: "", expiresAt: 0, riskLevel: .trusted, capabilityScopes: []
    )
    var decision = RequestProofDecision(decision: .allow, reason: "")

    private(set) var lastRiskBitset: UInt64?
    private(set) var lastInstanceId: String?
    private(set) var lastAttestationToken: Data?
    private(set) var lastProof: RequestProof?

    func getNonce() throws -> Data { nonce }

    func verifyAttestation(
        nonce: Data,
        riskBitset: UInt64,
        buildHash: String,
        policyHash: String,
        instanceId: String,
        attestationToken: Data
    ) throws -> TrustSession {
        lastRiskBitset = riskBitset
        lastInstanceId = instanceId
        lastAttestationToken = attestationToken
        return session
    }

    func validateRequestProof(_ proof: RequestProof) throws -> RequestProofDecision {
        lastProof = proof
        return decision
    }
}
