import Foundation
@testable import KsealDesktop

/// Controllable `DesktopEnvironment` for deterministic probe unit tests. Every
/// field defaults to a benign, "clean, signed & notarized app" value; tests
/// override only what the probe under test inspects. Lets the platform-
/// independent probe logic be fully exercised on any host (including Linux CI),
/// and is the test double for the external code-signing/notary surface.
final class FakeDesktopEnvironment: DesktopEnvironment {
    var signing = CodeSigningInfo(
        isSigned: true,
        signatureValid: true,
        teamIdentifier: "ABCDE12345",
        signingIdentifier: "com.example.app",
        isNotarized: true,
        hardenedRuntimeEnabled: true,
        anchoredToApple: false,
        cdHashHex: "deadbeef"
    )
    var environment: [String: String] = [:]
    var foreignImages: [String] = []
    var traced = false
    var nativeDebugger: Int32 = -1
    var nativeHook: Int32 = -1
    var fileDigests: [String: String] = [:]
    var bundleId: String? = "com.example.app"

    func codeSigningInfo() -> CodeSigningInfo { signing }
    func environmentVariable(_ name: String) -> String? { environment[name] }
    func foreignLoadedImagePaths() -> [String] { foreignImages }
    func isTraced() -> Bool { traced }
    func nativeDebuggerPresent() -> Int32 { nativeDebugger }
    func nativeHookPresent() -> Int32 { nativeHook }
    func sha256OfFile(_ path: String) -> String? { fileDigests[path] }
    var bundleIdentifier: String? { bundleId }
}
