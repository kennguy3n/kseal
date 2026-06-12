import Foundation

/// Detects dynamic-instrumentation frameworks by scanning loaded Mach-O image
/// names (Substrate/Substitute/libhooker, Frida, Cycript), the
/// `DYLD_INSERT_LIBRARIES` injection vector, and Frida's default control ports.
struct HookDetector: Probe {
    let id = "hook"
    private let env: DeviceEnvironment

    init(_ env: DeviceEnvironment) { self.env = env }

    func evaluate() -> Set<RiskSignal> {
        if imagesContainHooks() || env.environmentVariable("DYLD_INSERT_LIBRARIES") != nil || fridaPortOpen() {
            return [.hooking]
        }
        return []
    }

    private func imagesContainHooks() -> Bool {
        let images = env.loadedLibraryNames()
        guard !images.isEmpty else { return false }
        return images.contains { name in
            let lower = name.lowercased()
            return Self.markers.contains { lower.contains($0) }
        }
    }

    private func fridaPortOpen() -> Bool {
        env.isLoopbackPortOpen(27042) || env.isLoopbackPortOpen(27043)
    }

    static let markers = [
        "mobilesubstrate", "cydiasubstrate", "substrate", "substitute",
        "libhooker", "frida", "frida-agent", "frida-gadget", "cycript", "cynject",
    ]
}
