import Foundation

/// Narrow seam over the raw OS/platform surface the probes inspect.
///
/// Probes depend on this protocol rather than Darwin/UIKit APIs directly so
/// they stay deterministic and unit-testable on any host (a fake environment
/// supplies controlled inputs) while the production `AppleDeviceEnvironment`
/// reads the real device. Only public Apple APIs back the production
/// implementation — no private APIs (an explicit App Review requirement). None
/// of these methods perform network I/O.
protocol DeviceEnvironment {
    /// Whether a path exists (does not follow into restricted dirs that throw).
    func fileExists(_ path: String) -> Bool

    /// Whether `path` is a symbolic link (jailbreaks often relink system dirs).
    func isSymlink(_ path: String) -> Bool

    /// Attempts to create+delete a file outside the app sandbox; success implies
    /// a broken sandbox (jailbreak). Always false on a stock device.
    func canWriteOutsideSandbox() -> Bool

    /// Reads a process environment variable (e.g. `DYLD_INSERT_LIBRARIES`).
    func environmentVariable(_ name: String) -> String?

    /// Whether this is a simulator build/run (`TARGET_OS_SIMULATOR`).
    var isSimulator: Bool { get }

    /// Whether the process is being traced (`sysctl` `P_TRACED`).
    func isTraced() -> Bool

    /// Names of the currently loaded Mach-O images (`_dyld_get_image_name`).
    func loadedLibraryNames() -> [String]

    /// Whether a TCP port accepts connections on loopback (e.g. Frida 27042).
    func isLoopbackPortOpen(_ port: UInt16) -> Bool

    /// Configured system HTTP proxy host, or nil when none.
    func proxyHost() -> String?

    /// The running bundle's identifier.
    var bundleIdentifier: String? { get }

    /// Whether the bundle contains an `embedded.mobileprovision` (dev/enterprise/ad-hoc, not App Store).
    var hasEmbeddedMobileProvision: Bool { get }

    /// Whether an App Store receipt is present.
    var hasAppStoreReceipt: Bool { get }
}
