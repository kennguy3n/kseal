import Foundation

/// Detects dynamic-library injection: the `DYLD_INSERT_LIBRARIES` /
/// `DYLD_FRAMEWORK_PATH` insertion vectors and foreign Mach-O images loaded from
/// outside the app bundle and the OS. Injection is the macOS analogue of the
/// mobile hooking signal. Also consults the native (Rust) dyld-image scan over
/// the trust-core C ABI; the native result raises a signal only on an explicit
/// `== 1` and an unavailable check (negative sentinel) contributes nothing.
///
/// The native scan reports a single tri-state over all dyld images, so it cannot
/// apply the per-path `isAllowed` enterprise allowlist. To preserve the
/// allowlist contract it is consulted only when no allowlist is configured
/// (`consultNativeHook`); a managed deployment that sets an allowlist gets the
/// allowlist-aware managed checks instead, so a sanctioned module whose path
/// happens to contain a marker substring cannot raise a false positive.
struct DylibInjectionProbe: Probe {
    let id = "macos.dylibInjection"
    private let env: DesktopEnvironment
    private let isAllowed: (String) -> Bool
    private let consultNativeHook: Bool

    /// dyld variables that force-load attacker-controlled code into the process.
    private static let injectionEnvVars = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_LIBRARY_PATH",
    ]

    /// - Parameter isAllowed: enterprise allowlist predicate; a path it accepts
    ///   is a sanctioned plugin/agent and does not raise the signal. The default
    ///   allows nothing, preserving the strict (pre-policy) behavior.
    /// - Parameter consultNativeHook: whether to consult the allowlist-unaware
    ///   native dyld scan. Defaults to `true` (strict, no allowlist); the SDK
    ///   passes `false` when an enterprise injection allowlist is configured.
    init(
        _ env: DesktopEnvironment,
        isAllowed: @escaping (String) -> Bool = { _ in false },
        consultNativeHook: Bool = true
    ) {
        self.env = env
        self.isAllowed = isAllowed
        self.consultNativeHook = consultNativeHook
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
        if consultNativeHook, env.nativeHookPresent() == 1 {
            return [.hooking]
        }
        return []
    }
}
