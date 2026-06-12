import Foundation

/// Detects execution under the iOS Simulator via the build-time
/// `TARGET_OS_SIMULATOR` flag and the simulator's environment markers.
struct SimulatorDetector: Probe {
    let id = "simulator"
    private let env: DeviceEnvironment

    init(_ env: DeviceEnvironment) { self.env = env }

    func evaluate() -> Set<RiskSignal> {
        if env.isSimulator || env.environmentVariable("SIMULATOR_DEVICE_NAME") != nil {
            return [.simulator, .environment]
        }
        return []
    }
}
