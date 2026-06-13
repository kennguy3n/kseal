import Foundation

/// Result of inspecting the running app's code signature, notarization, and
/// runtime hardening. Produced by a `DesktopEnvironment` and consumed by the
/// integrity probes. Every field is a coarse, non-PII fact — never a raw
/// certificate or path.
public struct CodeSigningInfo: Equatable, Sendable {
    /// Whether the running code carries a code signature at all.
    public var isSigned: Bool
    /// Whether the signature is statically valid (CDHash/resources intact,
    /// `SecStaticCodeCheckValidity` succeeded).
    public var signatureValid: Bool
    /// The signing Team Identifier (`kSecCodeInfoTeamIdentifier`), or nil when
    /// unsigned / ad-hoc.
    public var teamIdentifier: String?
    /// The code-signing identifier (`kSecCodeInfoIdentifier`), typically the
    /// bundle id baked into the signature.
    public var signingIdentifier: String?
    /// Whether the binary passed a notarization assessment (Gatekeeper accepts
    /// it / a stapled ticket is present).
    public var isNotarized: Bool
    /// Whether the hardened-runtime code-signing flag is set
    /// (`kSecCodeSignatureRuntime`, `0x10000`).
    public var hardenedRuntimeEnabled: Bool
    /// Whether the signature chains to the Apple root (a platform/Apple-signed
    /// binary). Informational; not required for third-party apps.
    public var anchoredToApple: Bool
    /// Lowercase-hex SHA-256 CDHash of the code directory, or nil when unsigned.
    public var cdHashHex: String?

    public init(
        isSigned: Bool = false,
        signatureValid: Bool = false,
        teamIdentifier: String? = nil,
        signingIdentifier: String? = nil,
        isNotarized: Bool = false,
        hardenedRuntimeEnabled: Bool = false,
        anchoredToApple: Bool = false,
        cdHashHex: String? = nil
    ) {
        self.isSigned = isSigned
        self.signatureValid = signatureValid
        self.teamIdentifier = teamIdentifier
        self.signingIdentifier = signingIdentifier
        self.isNotarized = isNotarized
        self.hardenedRuntimeEnabled = hardenedRuntimeEnabled
        self.anchoredToApple = anchoredToApple
        self.cdHashHex = cdHashHex
    }
}

/// Narrow seam over the macOS code-signing / runtime surface the probes inspect.
///
/// Probes depend on this protocol rather than the Security/MachO frameworks
/// directly so they stay deterministic and unit-testable on any host (a fake
/// environment supplies controlled inputs) while the production
/// `MacDesktopEnvironment` reads the real process. This protocol is also the
/// **mock boundary for the external OS attestation/notary calls**: the
/// production implementation issues the real `SecStaticCode` / `SecAssessment`
/// queries; tests substitute a fake. Only public, App-Store / Gatekeeper-safe
/// Apple APIs back the production implementation — no private/SPI calls. None of
/// these methods perform network I/O.
protocol DesktopEnvironment {
    /// Inspects the running app's code signature / notarization / hardening.
    func codeSigningInfo() -> CodeSigningInfo

    /// Reads a process environment variable (e.g. `DYLD_INSERT_LIBRARIES`).
    func environmentVariable(_ name: String) -> String?

    /// Paths of dynamically loaded Mach-O images that are *not* part of the app
    /// bundle or the OS (`/System`, `/usr/lib`) — candidate injected dylibs.
    func foreignLoadedImagePaths() -> [String]

    /// Whether the process is being traced by a debugger (`sysctl` `P_TRACED`).
    func isTraced() -> Bool

    /// The running app's bundle identifier, when available.
    var bundleIdentifier: String? { get }
}
