import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Detects when the screen is being captured, recorded, or AirPlay-mirrored — a
/// credential/OTP exfiltration vector (`RiskSignal.screenCapture`).
///
/// Two synchronously-readable UIKit signals are fused via `ScreenCaptureMonitor`:
///
///  1. **Active capture** — `UIScreen.main.isCaptured` is `true` while the
///     screen is being recorded or mirrored (ReplayKit, AirPlay, QuickTime).
///     `UIScreen.main` is main-thread-only, so the monitor samples it on the
///     main thread (at init and on `UIScreen.capturedDidChangeNotification`),
///     caches the value, and lets `evaluate()` read the cache from any thread.
///  2. **Screenshots** — `UIApplication.userDidTakeScreenshotNotification`
///     fires *after* the user grabs a still; the monitor observes it within
///     this file and latches the observation until cleared.
///
/// The probe is constructed with no `DeviceEnvironment` because the live state
/// is `UIScreen`/`UIApplication`-scoped rather than a device setting. On hosts
/// without UIKit (the `swift test` host) both signals are unavailable and the
/// probe degrades to "nothing observed".
///
/// False positives: `isCaptured` is also `true` for legitimate casting
/// (AirPlay to an Apple TV, screen sharing in a call). iOS exposes no public
/// API to distinguish a benign mirror from a malicious one, so we report the
/// signal and defer the disposition (e.g. step-up vs. block) to the server-side
/// policy engine rather than guessing on-device.
struct ScreenCaptureDetector: Probe {
    let id = "screen_capture"

    func evaluate() -> Set<RiskSignal> {
        ScreenCaptureMonitor.shared.evaluate()
    }
}

/// Tracks live screen-capture state for the `screen_capture` probe. A single
/// shared instance observes screenshot and capture-change notifications for the
/// process lifetime, caching `UIScreen.isCaptured` from the main thread.
final class ScreenCaptureMonitor {
    static let shared = ScreenCaptureMonitor()

    private let lock = NSLock()
    private var screenshotObserved = false

    #if canImport(UIKit)
    /// Cached `UIScreen.main.isCaptured`. Written only on the main thread (the
    /// initial sample and `capturedDidChangeNotification`) and read under
    /// `lock` from any thread by `evaluate()`. Caching keeps the probe pipeline
    /// off the main-thread-only `UIScreen.main`, which would otherwise trip the
    /// Main Thread Checker in debug builds.
    private var captured = false
    private var screenshotObserver: NSObjectProtocol?
    private var captureObserver: NSObjectProtocol?
    #endif

    private init() {
        beginObserving()
    }

    deinit {
        #if canImport(UIKit)
        if let observer = screenshotObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        if let observer = captureObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        #endif
    }

    /// Fused detection: an active capture/mirror (`UIScreen.isCaptured`) or an
    /// observed screenshot yields `.screenCapture`.
    func evaluate() -> Set<RiskSignal> {
        Self.assess(isCaptured: isScreenCaptured(), screenshotObserved: hasObservedScreenshot())
    }

    /// Pure detection rule, host-agnostic so it is deterministic in unit tests.
    static func assess(isCaptured: Bool, screenshotObserved: Bool) -> Set<RiskSignal> {
        (isCaptured || screenshotObserved) ? [.screenCapture] : []
    }

    /// Whether a screenshot has been observed since the last clear.
    func hasObservedScreenshot() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return screenshotObserved
    }

    /// Clears a latched screenshot observation (e.g. after the host reacts).
    func clearScreenshotObservation() {
        lock.lock(); defer { lock.unlock() }
        screenshotObserved = false
    }

    /// Latches a screenshot observation. Invoked by the notification handler.
    func recordScreenshot() {
        lock.lock(); defer { lock.unlock() }
        screenshotObserved = true
    }

    private func isScreenCaptured() -> Bool {
        #if canImport(UIKit)
        lock.lock(); defer { lock.unlock() }
        return captured
        #else
        return false
        #endif
    }

    #if canImport(UIKit)
    /// Stores the latest capture state. Only ever called on the main thread.
    private func setCaptured(_ value: Bool) {
        lock.lock(); defer { lock.unlock() }
        captured = value
    }
    #endif

    private func beginObserving() {
        #if canImport(UIKit)
        screenshotObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.recordScreenshot()
        }
        captureObserver = NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.setCaptured(UIScreen.main.isCaptured)
        }
        // Seed the initial value on the main thread.
        let sampleInitial = { [weak self] in self?.setCaptured(UIScreen.main.isCaptured) }
        if Thread.isMainThread {
            sampleInitial()
        } else {
            DispatchQueue.main.async(execute: sampleInitial)
        }
        #endif
    }
}
