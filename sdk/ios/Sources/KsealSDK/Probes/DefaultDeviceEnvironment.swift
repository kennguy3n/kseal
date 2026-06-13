import Foundation

/// Returns the production device environment for the current platform.
func makeDefaultDeviceEnvironment() -> DeviceEnvironment {
    #if canImport(Darwin)
    return AppleDeviceEnvironment()
    #else
    return UnavailableDeviceEnvironment()
    #endif
}

#if !canImport(Darwin)
/// Benign environment used when building/testing on non-Apple hosts (Linux CI).
/// Every accessor reports "nothing observed" so the package compiles and the
/// platform-independent probe logic can be unit-tested with a fake instead.
struct UnavailableDeviceEnvironment: DeviceEnvironment {
    func fileExists(_ path: String) -> Bool { false }
    func isSymlink(_ path: String) -> Bool { false }
    func canWriteOutsideSandbox() -> Bool { false }
    func environmentVariable(_ name: String) -> String? { nil }
    var isSimulator: Bool { false }
    func isTraced() -> Bool { false }
    func loadedLibraryNames() -> [String] { [] }
    func isLoopbackPortOpen(_ port: UInt16) -> Bool { false }
    func proxyHost() -> String? { nil }
    var bundleIdentifier: String? { nil }
    var hasEmbeddedMobileProvision: Bool { false }
    var hasAppStoreReceipt: Bool { false }
}
#endif
