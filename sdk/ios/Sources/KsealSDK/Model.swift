import Foundation

/// Coarse confidence in a signal or decision. Mirrors `kseal.v1.Confidence`.
public enum Confidence: Int32, Sendable {
    case unspecified = 0
    case low = 1
    case medium = 2
    case high = 3

    init(code: Int32) {
        self = Confidence(rawValue: code) ?? .unspecified
    }
}

/// Fused trust classification for an app instance. Mirrors `kseal.v1.TrustLevel`.
///
/// `unspecified` is reported when no signed policy is loaded (thresholds are
/// required to map a score to a level).
public enum TrustLevel: Int32, Sendable {
    case unspecified = 0
    case trusted = 1
    case lowRisk = 2
    case mediumRisk = 3
    case highRisk = 4
    case critical = 5

    init(code: Int32) {
        self = TrustLevel(rawValue: code) ?? .unspecified
    }
}

/// Telemetry event categories emitted by the SDK. Mirrors `kseal.v1.EventType`.
public enum EventType: Int32, Sendable {
    case unspecified = 0
    case runtimeTamper = 1
    case debugger = 2
    case rootRisk = 3
    case attestationFail = 4
    case networkMitm = 5
    case policyDecision = 6
    case hookingDetected = 7
    case appIntegrityFail = 8
    case environmentRisk = 9
    case screenCapture = 10
    case overlayAbuse = 11
    case accessibilityAbuse = 12
    case maliciousIme = 13
    case remoteAccess = 14
}

/// Reporting platform. Mirrors `kseal.v1.Platform`.
public enum Platform: Int32, Sendable {
    case unspecified = 0
    case android = 1
    case ios = 2
}

/// Server-equivalent trust decision for the active policy. Mirrors
/// `kseal.v1.RequestProofResult.Decision`.
///
/// The SDK computes this locally with the exact mapping the server applies
/// (`risk.Decision(level, mode)`) and surfaces it through
/// `KsealSDK.onTrustDecision`; it never enforces the decision itself.
public enum Decision: Int32, Sendable {
    case unspecified = 0
    case allow = 1
    case stepUp = 2
    case deny = 3

    init(code: Int32) {
        self = Decision(rawValue: code) ?? .unspecified
    }
}

/// Result of an on-device risk evaluation.
public struct RiskAssessment: Sendable {
    /// Packed signal bitset (the only thing handed to the core / server).
    public let riskBits: UInt64
    /// Decoded set of detected signals (for local logging/UX; never exported raw).
    public let signals: Set<RiskSignal>
    /// Weighted risk score from the active policy (default weights when none loaded).
    public let score: UInt32
    /// Coarse confidence derived from the signal mix.
    public let confidence: Confidence
    /// Fused trust level under the active policy, or `.unspecified` when no policy is loaded.
    public let trustLevel: TrustLevel

    /// Whether no risk signals were observed.
    public var isClean: Bool { riskBits == 0 }
}

/// Per-request proof binding a request to the current trust token.
///
/// `proofBytes` is the serialized `kseal.v1.RequestProof` the host attaches to
/// the outbound request; the other fields are the inputs the SDK supplied.
public struct RequestProof: Sendable {
    public let tokenId: String
    public let requestHash: Data
    public let nonce: Data
    public let sequence: Int64
    public let proofBytes: Data
}
