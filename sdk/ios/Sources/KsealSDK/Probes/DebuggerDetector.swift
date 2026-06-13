import Foundation

/// Detects an attached debugger via the kernel `P_TRACED` flag (read with the
/// public `sysctl` API).
struct DebuggerDetector: Probe {
    let id = "debugger"
    private let env: DeviceEnvironment

    init(_ env: DeviceEnvironment) { self.env = env }

    func evaluate() -> Set<RiskSignal> {
        env.isTraced() ? [.debugger] : []
    }
}
