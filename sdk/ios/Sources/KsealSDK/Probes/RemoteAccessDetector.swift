import Foundation

/// Detects a remote-access / screen-sharing session controlling the device
/// (`RiskSignal.remoteAccess`) — the "remote takeover" social-engineering fraud
/// vector.
///
/// Wave-2 stub: registered but currently a no-op (returns no signals). On iOS
/// the live signal overlaps with screen capture (an active broadcast /
/// screen-share extension) and is wired to the UI layer in a follow-up.
struct RemoteAccessDetector: Probe {
    let id = "remote_access"

    func evaluate() -> Set<RiskSignal> { [] }
}
