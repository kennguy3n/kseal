import Foundation

/// Confirms the running app is notarized (Gatekeeper-accepted / stapled ticket
/// present). A non-notarized build under a notarization-required policy raises
/// an app-integrity signal. When the signature is missing entirely, the
/// `CodeSignatureProbe` already owns the tamper signal, so this probe stays
/// focused on the provenance dimension and does not double-count.
struct NotarizationProbe: Probe {
    let id = "macos.notarization"
    private let env: DesktopEnvironment
    private let policy: DesktopIntegrityPolicy

    init(_ env: DesktopEnvironment, policy: DesktopIntegrityPolicy) {
        self.env = env
        self.policy = policy
    }

    func evaluate() -> Set<RiskSignal> {
        guard policy.requireNotarization else { return [] }
        let info = env.codeSigningInfo()
        // Only assess notarization for a signed binary; an unsigned binary's
        // failure is fully described by the code-signature probe.
        guard info.isSigned else { return [] }
        return info.isNotarized ? [] : [.appIntegrity]
    }
}
