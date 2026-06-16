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
/// capture: the screen reports as captured while it is being recorded,
/// AirPlay-mirrored, or shared through a screen-share / broadcast extension.
/// This is a deliberately conservative, high-recall signal — it also trips for
/// benign user-initiated capture (the built-in screen recorder, personal
/// AirPlay to an Apple TV), so on iOS `.remoteAccess` favours recall over
/// precision: treat it as "the screen is being viewed/recorded by some party",
/// not as proof of a malicious remote operator. It degrades to "not observed"
/// off-device (e.g. macOS / Linux CI, where UIKit is unavailable).
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

    /// Reads the live screen-capture state on-device; always `false` where UIKit
    /// is unavailable (non-iOS hosts). `UIScreen` is a UIKit type that must be
    /// touched on the main thread, so the read is marshalled there when invoked
    /// from a background queue (avoids tripping the Main Thread Checker).
    private static func systemScreenCaptured() -> Bool {
        #if canImport(UIKit)
        if Thread.isMainThread {
            return mainThreadScreenCaptured()
        }
        return DispatchQueue.main.sync { mainThreadScreenCaptured() }
        #else
        return false
        #endif
    }

    #if canImport(UIKit)
    /// Must be called on the main thread. Prefers the active window scene's
    /// screen on iOS 16+ (where `UIScreen.main` is deprecated) and falls back to
    /// `UIScreen.main` on iOS 13–15 or when no window scene is connected.
    private static func mainThreadScreenCaptured() -> Bool {
        if #available(iOS 16.0, *) {
            let windowScenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            let scene = windowScenes.first { $0.activationState == .foregroundActive } ?? windowScenes.first
            if let scene = scene {
                return scene.screen.isCaptured
            }
        }
        return UIScreen.main.isCaptured
    }
    #endif
}
