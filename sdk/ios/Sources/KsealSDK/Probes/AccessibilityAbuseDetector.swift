import Foundation

/// Abusive accessibility services have no iOS analogue — iOS exposes no
/// third-party accessibility-service mechanism that can read or inject across
/// apps — so this probe is a **permanent no-op on iOS**, present only for
/// cross-platform probe-roster and `RiskSignal` layout parity
/// (`RiskSignal.accessibilityAbuse` is an Android-only vector in practice).
struct AccessibilityAbuseDetector: Probe {
    let id = "accessibility"

    func evaluate() -> Set<RiskSignal> { [] }
}
