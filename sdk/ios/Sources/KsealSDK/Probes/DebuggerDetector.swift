import Foundation

/// Detects an attached debugger via the kernel `P_TRACED` flag (read with the
/// public `sysctl` API), and also consults the native (Rust) tracer check over
/// the trust-core C ABI. The native result raises a signal only on an explicit
/// `== 1`; an unavailable check (negative sentinel) contributes nothing, so it
/// can never cause a false positive.
struct DebuggerDetector: Probe {
    let id = "debugger"
    private let env: DeviceEnvironment

    init(_ env: DeviceEnvironment) { self.env = env }

    func evaluate() -> Set<RiskSignal> {
        (env.isTraced() || env.nativeDebuggerPresent() == 1) ? [.debugger] : []
    }
}
