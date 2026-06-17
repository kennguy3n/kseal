import Foundation
@testable import KsealSDK

/// Controllable `DeviceEnvironment` for deterministic probe unit tests. Every
/// field defaults to a benign, "clean device" value; tests override only what
/// the probe under test inspects. Lets the platform-independent probe logic be
/// fully exercised on any host (including Linux CI).
final class FakeDeviceEnvironment: DeviceEnvironment {
    var existingFiles: Set<String> = []
    var symlinks: Set<String> = []
    var canWriteOutside = false
    var environment: [String: String] = [:]
    var simulator = false
    var traced = false
    var images: [String] = ["/usr/lib/libSystem.B.dylib", "/usr/lib/libobjc.A.dylib"]
    var openPorts: Set<UInt16> = []
    var nativeDebugger: Int32 = -1
    var nativeHook: Int32 = -1
    var proxy: String?
    var fileDigests: [String: String] = [:]
    var bundleId: String? = "com.example.app"
    var embeddedMobileProvision = false
    var appStoreReceipt = true

    func fileExists(_ path: String) -> Bool { existingFiles.contains(path) }
    func isSymlink(_ path: String) -> Bool { symlinks.contains(path) }
    func canWriteOutsideSandbox() -> Bool { canWriteOutside }
    func environmentVariable(_ name: String) -> String? { environment[name] }
    var isSimulator: Bool { simulator }
    func isTraced() -> Bool { traced }
    func loadedLibraryNames() -> [String] { images }
    func isLoopbackPortOpen(_ port: UInt16) -> Bool { openPorts.contains(port) }
    func nativeDebuggerPresent() -> Int32 { nativeDebugger }
    func nativeHookPresent() -> Int32 { nativeHook }
    func proxyHost() -> String? { proxy }
    func sha256OfFile(_ path: String) -> String? { fileDigests[path] }
    var bundleIdentifier: String? { bundleId }
    var hasEmbeddedMobileProvision: Bool { embeddedMobileProvision }
    var hasAppStoreReceipt: Bool { appStoreReceipt }
}
