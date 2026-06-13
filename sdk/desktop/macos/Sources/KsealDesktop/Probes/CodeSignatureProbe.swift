import Foundation

/// Verifies the running app's code signature: presence + static validity, and
/// (when the policy configures it) the signing Team Identifier and code-signing
/// identifier. A broken signature is reported as tamper + app-integrity; a
/// mismatched team / identifier is reported as repackaging.
struct CodeSignatureProbe: Probe {
    let id = "macos.codeSignature"
    private let env: DesktopEnvironment
    private let policy: DesktopIntegrityPolicy

    init(_ env: DesktopEnvironment, policy: DesktopIntegrityPolicy) {
        self.env = env
        self.policy = policy
    }

    func evaluate() -> Set<RiskSignal> {
        var signals = Set<RiskSignal>()
        let info = env.codeSigningInfo()

        if policy.requireValidSignature, !(info.isSigned && info.signatureValid) {
            signals.insert(.tamper)
            signals.insert(.appIntegrity)
        }

        if let expected = policy.expectedTeamIdentifier, !expected.isEmpty,
           info.teamIdentifier != expected {
            signals.insert(.repackaged)
            signals.insert(.appIntegrity)
        }

        if let expected = policy.expectedSigningIdentifier, !expected.isEmpty,
           info.signingIdentifier != expected {
            signals.insert(.repackaged)
            signals.insert(.appIntegrity)
        }

        return signals
    }
}
