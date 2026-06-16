import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Detects an active remote-view / screen-share session controlling the device
/// (`RiskSignal.remoteAccess`) — the "remote takeover" social-engineering fraud
/// vector.
///
/// Unlike Android, iOS exposes neither the list of installed third-party apps
/// nor a generic "remote control" API (the private surfaces that would reveal
/// them are an App Review rejection), so the only first-party signal is screen
/// capture: `UIScreen.main.isCaptured` is `true` while the display is being
/// recorded, AirPlay-mirrored, or shared through a screen-share/broadcast
/// extension — i.e. a remote party is viewing the screen. The check is
/// deliberately conservative (a single, documented public-API signal) and
/// degrades to "not observed" off-device (e.g. macOS / Linux CI, where UIKit
/// is unavailable).
///
/// The capture read is injected so the platform-independent logic stays fully
/// unit-testable on any host; production uses the `UIScreen`-backed default.
struct RemoteAccessDetector: Probe {
    let id = "remote_access"

    private let isScreenCaptured: () -> Bool

    /// Production initializer: reads the live `UIScreen` capture state.
    init() {
        self.init(isScreenCaptured: RemoteAccessDetector.systemScreenCaptured)
    }

    /// Test seam: inject a deterministic capture state.
    init(isScreenCaptured: @escaping () -> Bool) {
        self.isScreenCaptured = isScreenCaptured
    }

    func evaluate() -> Set<RiskSignal> {
        isScreenCaptured() ? [.remoteAccess] : []
    }

    /// Reads `UIScreen.main.isCaptured` on-device; always `false` where UIKit is
    /// unavailable (non-iOS hosts).
    private static func systemScreenCaptured() -> Bool {
        #if canImport(UIKit)
        return UIScreen.main.isCaptured
        #else
        return false
        #endif
    }
}
