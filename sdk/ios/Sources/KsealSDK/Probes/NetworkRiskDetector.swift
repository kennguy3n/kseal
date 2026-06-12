import Foundation

/// Detects network-interception posture: a configured system HTTP proxy (the
/// most common MITM enabler reachable via public APIs on iOS). Pinning failures
/// are reported separately by the transport layer via
/// `KsealSDK.reportPinningFailure()`.
struct NetworkRiskDetector: Probe {
    let id = "network"
    private let env: DeviceEnvironment

    init(_ env: DeviceEnvironment) { self.env = env }

    func evaluate() -> Set<RiskSignal> {
        if let host = env.proxyHost(), !host.isEmpty {
            return [.proxy, .networkMitm]
        }
        return []
    }
}
