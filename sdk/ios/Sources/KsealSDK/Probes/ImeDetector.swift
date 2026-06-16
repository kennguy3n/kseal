import Foundation

/// Malicious third-party keyboards are sandboxed on iOS and, without the user
/// granting "Full Access", cannot exfiltrate keystrokes the way a malicious
/// Android IME can. This probe is therefore a **permanent no-op on iOS**,
/// present only for cross-platform probe-roster and `RiskSignal` layout parity
/// (`RiskSignal.maliciousIme` is an Android-only vector in practice).
struct ImeDetector: Probe {
    let id = "ime"

    func evaluate() -> Set<RiskSignal> { [] }
}
