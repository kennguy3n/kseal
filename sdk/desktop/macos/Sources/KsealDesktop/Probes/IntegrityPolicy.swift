import Foundation

/// Expected-integrity baseline for the protected macOS app, supplied by the
/// integrator / signed config.
///
/// A disabled check (false flag) or an empty/nil expectation contributes no
/// signal, so an unconfigured baseline can never raise a false positive.
public struct DesktopIntegrityPolicy: Sendable {
    /// The legitimate signing Team Identifier (e.g. `ABCDE12345`). A mismatch
    /// indicates a re-signed / repackaged build. Nil disables the check.
    public let expectedTeamIdentifier: String?
    /// The legitimate code-signing identifier (bundle id). A mismatch indicates
    /// repackaging. Nil disables the check.
    public let expectedSigningIdentifier: String?
    /// When true, an unsigned or statically invalid signature raises a signal.
    public let requireValidSignature: Bool
    /// When true, a binary that is not notarized raises a signal.
    public let requireNotarization: Bool
    /// When true, a binary built without the hardened runtime raises a signal.
    public let requireHardenedRuntime: Bool

    public init(
        expectedTeamIdentifier: String? = nil,
        expectedSigningIdentifier: String? = nil,
        requireValidSignature: Bool = true,
        requireNotarization: Bool = true,
        requireHardenedRuntime: Bool = true
    ) {
        self.expectedTeamIdentifier = expectedTeamIdentifier
        self.expectedSigningIdentifier = expectedSigningIdentifier
        self.requireValidSignature = requireValidSignature
        self.requireNotarization = requireNotarization
        self.requireHardenedRuntime = requireHardenedRuntime
    }
}
