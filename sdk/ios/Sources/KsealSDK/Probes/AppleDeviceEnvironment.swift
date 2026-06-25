#if canImport(Darwin)
import Foundation
import Darwin
import CKseal
#if canImport(MachO)
import MachO
#endif
#if canImport(CFNetwork)
import CFNetwork
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Production `DeviceEnvironment` reading the real Apple device using only
/// public APIs (no private/SPI calls — an explicit App Review requirement).
final class AppleDeviceEnvironment: DeviceEnvironment {

    private let bundle: Bundle

    init(bundle: Bundle = .main) {
        self.bundle = bundle
    }

    func fileExists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    func isSymlink(_ path: String) -> Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else { return false }
        return (attrs[.type] as? FileAttributeType) == .typeSymbolicLink
    }

    func canWriteOutsideSandbox() -> Bool {
        // On a stock device the sandbox denies writes outside the container; a
        // successful write to a system path indicates a broken sandbox.
        let probePath = "/private/" + UUID().uuidString
        do {
            try "kseal".write(toFile: probePath, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: probePath)
            return true
        } catch {
            return false
        }
    }

    func environmentVariable(_ name: String) -> String? {
        ProcessInfo.processInfo.environment[name]
    }

    var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
        #endif
    }

    func isTraced() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, u_int(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    func loadedLibraryNames() -> [String] {
        #if canImport(MachO)
        var names: [String] = []
        let count = _dyld_image_count()
        var i: UInt32 = 0
        while i < count {
            if let cname = _dyld_get_image_name(i) {
                names.append(String(cString: cname))
            }
            i += 1
        }
        return names
        #else
        return []
        #endif
    }

    func isLoopbackPortOpen(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let connected = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return connected == 0
    }

    func nativeDebuggerPresent() -> Int32 {
        // Native (Rust) sysctl `P_TRACED` check over the trust-core C ABI.
        // Returns 1/0/-1; the SDK is fail-safe on the negative sentinel.
        kseal_native_debugger_present()
    }

    func nativeHookPresent() -> Int32 {
        // Native (Rust) dyld-image scan for injected instrumentation.
        kseal_native_hook_present()
    }

    func proxyHost() -> String? {
        #if canImport(CFNetwork)
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return nil
        }
        if let host = settings[kCFNetworkProxiesHTTPProxy as String] as? String, !host.isEmpty {
            return host
        }
        #endif
        return nil
    }

    func sha256OfFile(_ path: String) -> String? {
        #if canImport(CryptoKit)
        // Memory-map (when safe) so large packaged artifacts are not fully
        // resident; any read failure degrades to nil ("could not measure").
        let url = URL(fileURLWithPath: path)
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #else
        return nil
        #endif
    }

    var bundleIdentifier: String? {
        bundle.bundleIdentifier
    }

    var hasEmbeddedMobileProvision: Bool {
        bundle.path(forResource: "embedded", ofType: "mobileprovision") != nil
    }

    var hasAppStoreReceipt: Bool {
        guard let url = bundle.appStoreReceiptURL else { return false }
        return FileManager.default.fileExists(atPath: url.path)
    }
}
#endif
