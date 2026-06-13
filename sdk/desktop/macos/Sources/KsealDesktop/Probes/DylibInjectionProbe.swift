import Foundation

/// Detects dynamic-library injection: the `DYLD_INSERT_LIBRARIES` /
/// `DYLD_FRAMEWORK_PATH` insertion vectors and foreign Mach-O images loaded from
/// outside the app bundle and the OS. Injection is the macOS analogue of the
/// mobile hooking signal.
struct DylibInjectionProbe: Probe {
    let id = "macos.dylibInjection"
    private let env: DesktopEnvironment

    /// dyld variables that force-load attacker-controlled code into the process.
    private static let injectionEnvVars = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_LIBRARY_PATH",
    ]

    init(_ env: DesktopEnvironment) {
        self.env = env
    }

    func evaluate() -> Set<RiskSignal> {
        for name in Self.injectionEnvVars {
            if let value = env.environmentVariable(name), !value.isEmpty {
                return [.hooking]
            }
        }
        if !env.foreignLoadedImagePaths().isEmpty {
            return [.hooking]
        }
        return []
    }
}
