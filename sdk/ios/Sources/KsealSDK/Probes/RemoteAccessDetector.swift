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
/// unit-testable on any host. In production it reads a process-wide cache
/// (`ScreenCaptureMonitor`) that is seeded and refreshed on the main thread via
/// `UIScreen.capturedDidChangeNotification`, so `evaluate()` can run on any
/// thread without touching UIKit off the main thread and without a
/// deadlock-prone synchronous main-thread hop.
struct RemoteAccessDetector: Probe {
    let id = "remote_access"

    private let isScreenCaptured: () -> Bool

    /// Production initializer: reads the cached, main-thread-maintained capture state.
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

    /// Last-published screen-capture state; always `false` where UIKit is
    /// unavailable (non-iOS hosts). Reads are lock-guarded and never touch UIKit
    /// directly, so this is safe to call from any thread.
    private static func systemScreenCaptured() -> Bool {
        #if canImport(UIKit)
        return ScreenCaptureMonitor.shared.isCaptured
        #else
        return false
        #endif
    }
}

#if canImport(UIKit)
/// Process-wide cache of `UIScreen` capture state.
///
/// `UIScreen` is a UIKit type that must be touched on the main thread, but a
/// probe's `evaluate()` may run on any thread. Rather than hop to the main
/// thread synchronously on every read — which risks a `DispatchQueue.main.sync`
/// deadlock if the caller is a background thread the main thread is waiting on —
/// the value is seeded once and thereafter refreshed on the main thread in
/// response to `UIScreen.capturedDidChangeNotification`. Readers just see the
/// last-published `Bool` behind a lock, so reads are non-blocking and thread-safe.
///
/// If the monitor is first touched off the main thread, setup is dispatched
/// there asynchronously; until it runs (typically the next runloop turn) reads
/// return the default `false`.
private final class ScreenCaptureMonitor {
    static let shared = ScreenCaptureMonitor()

    private let lock = NSLock()
    private var captured = false

    private init() {
        if Thread.isMainThread {
            start()
        } else {
            DispatchQueue.main.async { [weak self] in self?.start() }
        }
    }

    /// Thread-safe snapshot of the most recently published capture state.
    var isCaptured: Bool {
        lock.lock()
        defer { lock.unlock() }
        return captured
    }

    /// Seeds the cache and installs the change observer. Must run on the main thread.
    private func start() {
        refresh()
        NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in self?.refresh() }
    }

    /// Reads the live capture state (on the main thread) and publishes it.
    private func refresh() {
        let value = ScreenCaptureMonitor.currentScreenIsCaptured()
        lock.lock()
        captured = value
        lock.unlock()
    }

    /// Must be called on the main thread. Prefers the active window scene's screen
    /// on iOS 16+ (where `UIScreen.main` is deprecated) and falls back to
    /// `UIScreen.main` on iOS 13–15 or when no window scene is connected.
    private static func currentScreenIsCaptured() -> Bool {
        if #available(iOS 16.0, *) {
            let windowScenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            let scene = windowScenes.first { $0.activationState == .foregroundActive } ?? windowScenes.first
            if let scene = scene {
                return scene.screen.isCaptured
            }
        }
        return UIScreen.main.isCaptured
    }
}
#endif
