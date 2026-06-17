import Foundation

/// Runtime self-integrity baseline supplied by the protected build / signed
/// config: the expected SHA-256 of code and packaged-resource files measured at
/// build time.
///
/// When a map is empty the corresponding check is skipped — the SDK never
/// fabricates a baseline, so an unconfigured check contributes no signal and
/// cannot cause a false positive. Each entry maps an absolute on-device file
/// path to its expected lowercase-hex SHA-256.
///
/// - Parameters:
///   - expectedCodeSha256: code/library files; a successfully measured digest
///     that differs raises `.tamper` ("in-memory code/section checksum mismatch").
///   - expectedArtifactSha256: packaged artifacts/resources; a successfully
///     measured digest that differs raises `.appIntegrity` ("packaged
///     artifact/resource digest mismatch").
public struct TamperPolicy: Sendable {
    public let expectedCodeSha256: [String: String]
    public let expectedArtifactSha256: [String: String]

    public init(
        expectedCodeSha256: [String: String] = [:],
        expectedArtifactSha256: [String: String] = [:]
    ) {
        self.expectedCodeSha256 = expectedCodeSha256
        self.expectedArtifactSha256 = expectedArtifactSha256
    }
}

/// In-process runtime self-integrity loop: re-checksums the app's code and
/// packaged resources on every trust evaluation and compares each against the
/// build-time baseline in `TamperPolicy`.
///
/// Fail-safe by construction:
/// - an empty baseline map skips that check entirely (no baseline → no signal);
/// - a file whose digest cannot be measured (`sha256OfFile` returns nil)
///   contributes nothing — only a *successfully measured* digest that differs
///   from the baseline raises a signal.
///
/// Raises `.tamper` for code mismatches and `.appIntegrity` for
/// packaged-artifact mismatches. The SDK only raises signals; it never enforces.
struct SelfIntegrityDetector: Probe {
    let id = "selfIntegrity"
    private let env: DeviceEnvironment
    private let policy: TamperPolicy

    init(_ env: DeviceEnvironment, policy: TamperPolicy) {
        self.env = env
        self.policy = policy
    }

    func evaluate() -> Set<RiskSignal> {
        var signals = Set<RiskSignal>()

        if mismatchExists(policy.expectedCodeSha256) {
            signals.insert(.tamper)
        }
        if mismatchExists(policy.expectedArtifactSha256) {
            signals.insert(.appIntegrity)
        }

        return signals
    }

    /// True when at least one file in `expected` is measurable and its digest
    /// differs from the baseline. Unmeasurable files are skipped.
    private func mismatchExists(_ expected: [String: String]) -> Bool {
        guard !expected.isEmpty else { return false }
        for (path, baseline) in expected {
            guard let actual = env.sha256OfFile(path) else { continue }
            if actual.lowercased() != baseline.lowercased() {
                return true
            }
        }
        return false
    }
}
