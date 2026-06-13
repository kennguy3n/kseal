#if canImport(Darwin)
import Foundation
import Darwin
#if canImport(Security)
import Security
#endif
#if canImport(MachO)
import MachO
#endif

/// Production `DesktopEnvironment` reading the real macOS process using only
/// public, App-Store / Gatekeeper-safe Apple APIs (no private/SPI calls):
///
/// - **Code signature**: `SecCodeCopySelf` + `SecStaticCodeCheckValidity` +
///   `SecCodeCopySigningInformation` (signed status, static validity, team
///   identifier, signing identifier, code-signing flags, CDHash).
/// - **Hardened runtime**: the `kSecCodeSignatureRuntime` (`0x10000`) bit of
///   `kSecCodeInfoFlags`.
/// - **Notarization**: a Gatekeeper execute assessment (`SecAssessmentCreate`),
///   which succeeds only for a signed **and** notarized (and un-revoked) binary.
///
/// The signing inspection is computed once and cached: it is the only mildly
/// expensive call, and the probes each read the same snapshot, keeping the
/// aggregate evaluation well within the startup budget.
final class MacDesktopEnvironment: DesktopEnvironment {

    private let bundle: Bundle
    private let cacheLock = NSLock()
    private var cachedInfo: CodeSigningInfo?

    init(bundle: Bundle = .main) {
        self.bundle = bundle
    }

    func codeSigningInfo() -> CodeSigningInfo {
        cacheLock.lock(); defer { cacheLock.unlock() }
        if let cached = cachedInfo { return cached }
        let info = Self.inspect(bundle: bundle)
        cachedInfo = info
        return info
    }

    func environmentVariable(_ name: String) -> String? {
        ProcessInfo.processInfo.environment[name]
    }

    func foreignLoadedImagePaths() -> [String] {
        #if canImport(MachO)
        let bundlePath = bundle.bundleURL.standardizedFileURL.path
        var foreign: [String] = []
        let count = _dyld_image_count()
        var i: UInt32 = 0
        while i < count {
            if let cname = _dyld_get_image_name(i) {
                let path = String(cString: cname)
                if !Self.isSystemImage(path) && !path.hasPrefix(bundlePath) {
                    foreign.append(path)
                }
            }
            i += 1
        }
        return foreign
        #else
        return []
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

    var bundleIdentifier: String? { bundle.bundleIdentifier }

    // MARK: - Code-signing inspection

    /// OS image trees that are legitimately loaded into every process.
    private static func isSystemImage(_ path: String) -> Bool {
        path.hasPrefix("/System/") ||
            path.hasPrefix("/usr/lib/") ||
            path.hasPrefix("/usr/local/lib/swift") ||
            path.hasPrefix("/Library/Apple/")
    }

    #if canImport(Security)
    /// The hardened-runtime code-signing flag (`CS_RUNTIME`).
    private static let csRuntimeFlag: UInt32 = 0x1_0000

    private static func inspect(bundle: Bundle) -> CodeSigningInfo {
        var selfCode: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &selfCode) == errSecSuccess, let code = selfCode else {
            return CodeSigningInfo()
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess,
              let staticRef = staticCode else {
            return CodeSigningInfo()
        }

        // Static validity: CDHash + sealed resources intact across all slices.
        let checkFlags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        let signatureValid = SecStaticCodeCheckValidity(staticRef, checkFlags, nil) == errSecSuccess

        var info = CodeSigningInfo(isSigned: true, signatureValid: signatureValid)

        var signingInfo: CFDictionary?
        let infoFlags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        if SecCodeCopySigningInformation(staticRef, infoFlags, &signingInfo) == errSecSuccess,
           let dict = signingInfo as? [String: Any] {
            info.teamIdentifier = dict[kSecCodeInfoTeamIdentifier as String] as? String
            info.signingIdentifier = dict[kSecCodeInfoIdentifier as String] as? String
            if let flags = dict[kSecCodeInfoFlags as String] as? UInt32 {
                info.hardenedRuntimeEnabled = (flags & csRuntimeFlag) != 0
            }
            if let hashes = dict[kSecCodeInfoCdHashes as String] as? [Data], let primary = hashes.first {
                info.cdHashHex = primary.map { String(format: "%02x", $0) }.joined()
            }
            info.anchoredToApple = anchoredToAppleRoot(staticRef)
        }

        info.isNotarized = signatureValid && isNotarized(bundle.bundleURL)
        return info
    }

    /// Whether the code chains to the Apple root (a platform / Apple-signed
    /// binary). Uses the documented `anchor apple` requirement.
    private static func anchoredToAppleRoot(_ staticCode: SecStaticCode) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple" as CFString, SecCSFlags(), &requirement) == errSecSuccess,
              let req = requirement else {
            return false
        }
        return SecStaticCodeCheckValidity(staticCode, SecCSFlags(), req) == errSecSuccess
    }

    /// On-device notarization assessment via Gatekeeper. `SecAssessmentCreate`
    /// for an *execute* operation succeeds only when the binary is signed,
    /// notarized, and not revoked — exactly the provenance the probe needs.
    private static func isNotarized(_ url: URL) -> Bool {
        // `SecAssessmentCreate(path, flags, context, errors)` — the operation
        // type is supplied via the context dictionary, not a positional arg. The
        // call is audited, so the return is a managed `SecAssessment?` (ARC frees
        // it) while `errors` is an unmanaged out-param we must release ourselves.
        let context: CFDictionary = [
            kSecAssessmentContextKeyOperation as String: kSecAssessmentOperationTypeExecute
        ] as CFDictionary
        var error: Unmanaged<CFError>?
        let assessment = SecAssessmentCreate(
            url as CFURL,
            SecAssessmentFlags(rawValue: 0),
            context,
            &error
        )
        if let error { error.release(); return false }
        return assessment != nil
    }
    #else
    private static func inspect(bundle: Bundle) -> CodeSigningInfo { CodeSigningInfo() }
    #endif
}
#endif
