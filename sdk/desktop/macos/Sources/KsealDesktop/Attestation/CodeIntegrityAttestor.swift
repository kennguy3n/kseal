import Foundation

/// Produces the platform-attestation token submitted to `VerifyAttestation`.
///
/// This is the **external-attestation mock boundary**. Unlike iOS/Android,
/// macOS exposes no first-party remote attestation service for third-party apps
/// (App Attest / Play Integrity have no desktop analogue), so the default
/// implementation produces a *local* attestation derived from the verified
/// code-signing snapshot — no network and no external dependency. An integrator
/// that fronts a cloud KMS/HSM or a notary service plugs a real implementation
/// in here; tests inject a fake. The server fuses the on-device risk bitset with
/// whatever token this yields.
public protocol CodeIntegrityAttestor {
    /// Returns the attestation token bytes (empty when no external attestation
    /// is configured — the server then relies on the fused risk signals + the
    /// request-proof key binding).
    func attestationToken(for info: CodeSigningInfo) -> Data
}

/// Default attestor: a compact, non-PII local attestation built from the
/// verified code-signing identity (team identifier + CDHash). It carries no
/// secret and no personal data — only the signing provenance the server can
/// cross-check against the registered build.
public struct LocalCodeIntegrityAttestor: CodeIntegrityAttestor {
    public init() {}

    public func attestationToken(for info: CodeSigningInfo) -> Data {
        // Empty unless the binary is validly signed: an unsigned/invalid binary
        // has no provenance to attest, so we send nothing and let the fused risk
        // signals drive the server decision (fail-closed on the server side).
        guard info.isSigned, info.signatureValid else { return Data() }
        var fields: [String: String] = [:]
        if let team = info.teamIdentifier { fields["team"] = team }
        if let cdHash = info.cdHashHex { fields["cdhash"] = cdHash }
        if let identifier = info.signingIdentifier { fields["id"] = identifier }
        fields["notarized"] = info.isNotarized ? "1" : "0"
        guard let data = try? JSONSerialization.data(
            withJSONObject: fields, options: [.sortedKeys]
        ) else { return Data() }
        return data
    }
}
