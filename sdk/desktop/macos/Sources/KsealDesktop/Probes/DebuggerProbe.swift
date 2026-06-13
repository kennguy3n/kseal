import Foundation

/// Detects an attached debugger via the process trace flag (`sysctl` `P_TRACED`).
///
/// Disabled by default: per the desktop threat model
/// ([ARCHITECTURE.md#desktop-caution](../../../../../ARCHITECTURE.md)), debugging
/// is a legitimate developer/admin activity far more often than on mobile, so
/// aggressive anti-debug causes false positives early on. Integrators opt in
/// explicitly via `enabledProbes`.
struct DebuggerProbe: Probe {
    let id = "macos.debugger"
    private let env: DesktopEnvironment

    init(_ env: DesktopEnvironment) {
        self.env = env
    }

    func evaluate() -> Set<RiskSignal> {
        env.isTraced() ? [.debugger] : []
    }
}
