import Foundation

/// Verifies the hardened-runtime code-signing flag is set. The hardened runtime
/// blocks unsigned-code execution and `DYLD_INSERT_LIBRARIES` injection, so a
/// build shipped without it is a materially weaker (elevated-risk) environment.
struct HardenedRuntimeProbe: Probe {
    let id = "macos.hardenedRuntime"
    private let env: DesktopEnvironment
    private let policy: DesktopIntegrityPolicy

    init(_ env: DesktopEnvironment, policy: DesktopIntegrityPolicy) {
        self.env = env
        self.policy = policy
    }

    func evaluate() -> Set<RiskSignal> {
        guard policy.requireHardenedRuntime else { return [] }
        let info = env.codeSigningInfo()
        guard info.isSigned else { return [] }
        return info.hardenedRuntimeEnabled ? [] : [.environment]
    }
}
