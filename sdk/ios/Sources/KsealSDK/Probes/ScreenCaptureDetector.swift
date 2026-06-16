import Foundation

/// Detects when the screen is being captured or recorded — a credential/OTP
/// exfiltration vector (`RiskSignal.screenCapture`).
///
/// Wave-2 stub: registered in the probe pipeline but currently a no-op (returns
/// no signals), so this change introduces zero runtime behaviour. The live iOS
/// check is `UIScreen`-scoped (`isCaptured` plus the capture-did-change
/// notification) and is wired to the UI layer in a follow-up.
struct ScreenCaptureDetector: Probe {
    let id = "screen_capture"

    func evaluate() -> Set<RiskSignal> { [] }
}
