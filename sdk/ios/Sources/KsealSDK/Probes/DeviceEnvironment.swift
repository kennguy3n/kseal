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

    /// Result of the native (Rust) tracer check, run in-process via the trust
    /// core's C ABI: `1` (a debugger/tracer is attached), `0` (clean), or a
    /// negative value when the native library is unavailable. Fail-safe:
    /// callers raise a signal only on a strict `== 1`, so an unavailable check
    /// contributes nothing and can never cause a false positive.
    func nativeDebuggerPresent() -> Int32

    /// Result of the native (Rust) hooking-framework check (dyld image scan):
    /// `1` (instrumentation present), `0` (clean), or negative when
    /// unavailable. Same fail-safe contract as `nativeDebuggerPresent()`.
    func nativeHookPresent() -> Int32

    /// Configured system HTTP proxy host, or nil when none.
    func proxyHost() -> String?

    /// SHA-256 (hex, lowercase) of the file at `path`, computed by streaming its
    /// bytes, or nil when the file is missing / unreadable / cannot be digested.
    /// Used by the runtime self-integrity check to compare a packaged artifact
    /// or code file against a build-time baseline. Fail-safe: a nil result means
    /// "could not measure" and never raises a tamper signal.
    func sha256OfFile(_ path: String) -> String?

    /// The running bundle's identifier.
    var bundleIdentifier: String? { get }

    /// Whether the bundle contains an `embedded.mobileprovision` (dev/enterprise/ad-hoc, not App Store).
    var hasEmbeddedMobileProvision: Bool { get }

    /// Whether an App Store receipt is present.
    var hasAppStoreReceipt: Bool { get }
}
