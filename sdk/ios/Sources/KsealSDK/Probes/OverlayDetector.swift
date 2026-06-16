import Foundation

/// Tapjacking / overlay abuse has no iOS analogue: the platform does not let one
/// app draw windows over another, so this probe is a **permanent no-op on iOS**.
/// It exists only so the cross-platform probe roster and `RiskSignal` layout
/// (`RiskSignal.overlayAbuse`, an Android-only vector in practice) stay
/// identical across SDKs.
struct OverlayDetector: Probe {
    let id = "overlay"

    func evaluate() -> Set<RiskSignal> { [] }
}
