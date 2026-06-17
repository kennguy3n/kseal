import Foundation

/// Expected code/artifact SHA-256 baseline for the runtime self-integrity loop,
/// supplied by the protected build / signed config.
///
/// Both maps are skip-if-empty: an unconfigured baseline contributes no signal,
/// so it can never raise a false positive. The probe re-measures the on-disk
/// artifacts post-launch (and on each trust evaluation) and compares them to the
/// registered digests — it never fabricates a baseline.
public struct DesktopTamperPolicy: Sendable {
    /// `path` → expected lowercase-hex SHA-256 of the app's code (e.g. the
    /// main Mach-O executable / loaded frameworks). A mismatch raises `.tamper`.
    public let expectedCodeSha256: [String: String]
    /// `path` → expected lowercase-hex SHA-256 of packaged resources / artifacts
    /// (e.g. `Info.plist`, bundled assets). A mismatch raises `.appIntegrity`.
    public let expectedArtifactSha256: [String: String]

    public init(
        expectedCodeSha256: [String: String] = [:],
        expectedArtifactSha256: [String: String] = [:]
    ) {
        self.expectedCodeSha256 = expectedCodeSha256
        self.expectedArtifactSha256 = expectedArtifactSha256
    }
}

/// Runtime self-integrity loop: re-digests the app's code/resources and compares
/// against the build-time baseline in `DesktopTamperPolicy`. Raises `.tamper` on
/// a code-digest mismatch and `.appIntegrity` on an artifact-digest mismatch.
///
/// Complements `CodeSignatureProbe` (which validates the OS code signature) with
/// a content-digest check the integrator can pin to specific files. Fail-safe:
/// a file whose digest cannot be computed (missing/unreadable → `nil`) is
/// skipped and never raises a signal; an empty policy is fully silent.
struct SelfIntegrityProbe: Probe {
    let id = "macos.selfIntegrity"
    private let env: DesktopEnvironment
    private let policy: DesktopTamperPolicy

    init(_ env: DesktopEnvironment, policy: DesktopTamperPolicy) {
        self.env = env
        self.policy = policy
    }

    func evaluate() -> Set<RiskSignal> {
        var signals = Set<RiskSignal>()
        if mismatchExists(policy.expectedCodeSha256) { signals.insert(.tamper) }
        if mismatchExists(policy.expectedArtifactSha256) { signals.insert(.appIntegrity) }
        return signals
    }

    private func mismatchExists(_ expected: [String: String]) -> Bool {
        guard !expected.isEmpty else { return false }
        for (path, baseline) in expected {
            guard let actual = env.sha256OfFile(path) else { continue }
            if actual.lowercased() != baseline.lowercased() { return true }
        }
        return false
    }
}
