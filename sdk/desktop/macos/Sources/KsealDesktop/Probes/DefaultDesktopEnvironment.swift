import Foundation

/// Returns the production desktop environment for the current platform.
func makeDefaultDesktopEnvironment() -> DesktopEnvironment {
    #if canImport(Darwin)
    return MacDesktopEnvironment()
    #else
    return UnavailableDesktopEnvironment()
    #endif
}

#if !canImport(Darwin)
/// Benign environment used when building/testing on non-Apple hosts (Linux CI).
/// Every accessor reports "nothing observed" so the package compiles and the
/// platform-independent probe logic can be unit-tested with a fake instead.
struct UnavailableDesktopEnvironment: DesktopEnvironment {
    func codeSigningInfo() -> CodeSigningInfo { CodeSigningInfo() }
    func environmentVariable(_ name: String) -> String? { nil }
    func foreignLoadedImagePaths() -> [String] { [] }
    func isTraced() -> Bool { false }
    var bundleIdentifier: String? { nil }
}
#endif
