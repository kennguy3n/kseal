import Foundation

/// A minted trust session returned by `VerifyAttestation`.
public struct TrustSession: Sendable {
    public let tokenId: String
    public let signedToken: Data
    public let accepted: Bool
    public let rejectionReason: String
    public let expiresAt: Int64
    public let riskLevel: TrustLevel
    public let capabilityScopes: [String]
}

/// The server's decision after validating a per-request proof. Mirrors
/// `kseal.v1.RequestProofResult.Decision`.
public enum TrustDecision: String, Sendable {
    case unspecified = "DECISION_UNSPECIFIED"
    case allow = "DECISION_ALLOW"
    case stepUp = "DECISION_STEP_UP"
    case deny = "DECISION_DENY"
}

/// Outcome of validating a request proof.
public struct RequestProofDecision: Sendable {
    public let decision: TrustDecision
    public let reason: String
}

/// Errors surfaced by the trust-session transport.
public struct TrustSessionError: Error, CustomStringConvertible {
    public let message: String
    public var description: String { message }
}

/// Drives the device-plane trust flow against the existing `TrustService` RPCs
/// (`GetNonce` → `VerifyAttestation` → `ValidateRequestProof`).
///
/// The flow is identical to the one the mobile SDKs' host apps perform; this
/// client packages it for desktop hosts. It is **never** invoked at launch —
/// the host calls it explicitly to establish or refresh a session, satisfying
/// the no-launch-network budget.
public protocol TrustSessionClient {
    /// Requests a fresh single-use challenge nonce.
    func getNonce() throws -> Data

    /// Submits the locally fused risk state + platform attestation and returns
    /// the minted trust session.
    func verifyAttestation(
        nonce: Data,
        riskBitset: UInt64,
        buildHash: String,
        policyHash: String,
        instanceId: String,
        attestationToken: Data
    ) throws -> TrustSession

    /// Asks the server to validate a per-request proof and return its decision.
    func validateRequestProof(_ proof: RequestProof) throws -> RequestProofDecision
}
