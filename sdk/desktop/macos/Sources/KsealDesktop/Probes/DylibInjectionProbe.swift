import Foundation

/// Detects dynamic-library injection: the `DYLD_INSERT_LIBRARIES` /
/// `DYLD_FRAMEWORK_PATH` insertion vectors and foreign Mach-O images loaded from
/// outside the app bundle and the OS. Injection is the macOS analogue of the
/// mobile hooking signal.
struct DylibInjectionProbe: Probe {
    let id = "macos.dylibInjection"
    private let env: DesktopEnvironment
    private let isAllowed: (String) -> Bool

    /// dyld variables that force-load attacker-controlled code into the process.
    private static let injectionEnvVars = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_LIBRARY_PATH",
    ]

    /// - Parameter isAllowed: enterprise allowlist predicate; a path it accepts
    ///   is a sanctioned plugin/agent and does not raise the signal. The default
    ///   allows nothing, preserving the strict (pre-policy) behavior.
    init(_ env: DesktopEnvironment, isAllowed: @escaping (String) -> Bool = { _ in false }) {
        self.env = env
        self.isAllowed = isAllowed
    }

    func evaluate() -> Set<RiskSignal> {
        for name in Self.injectionEnvVars {
            guard let value = env.environmentVariable(name), !value.isEmpty else { continue }
            let paths = value.split(separator: ":", omittingEmptySubsequences: true).map(String.init)
            if paths.isEmpty || paths.contains(where: { !isAllowed($0) }) {
                return [.hooking]
            }
        }
        if env.foreignLoadedImagePaths().contains(where: { !isAllowed($0) }) {
            return [.hooking]
        }
        return []
    }
}
