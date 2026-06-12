import Foundation

/// Expected-integrity baseline supplied by the protected build / signed config.
///
/// When a check is disabled / a field is empty it contributes no signal, so an
/// unconfigured baseline cannot cause false positives.
///
/// - Parameters:
///   - requireAppStoreDistribution: when true, an embedded provisioning profile
///     or a missing App Store receipt (i.e. not an App Store build) raises an
///     integrity signal. Leave false for enterprise/ad-hoc distribution.
///   - expectedBundleId: the legitimate bundle identifier; a mismatch indicates repackaging.
public struct IntegrityPolicy: Sendable {
    public let requireAppStoreDistribution: Bool
    public let expectedBundleId: String?

    public init(requireAppStoreDistribution: Bool = false, expectedBundleId: String? = nil) {
        self.requireAppStoreDistribution = requireAppStoreDistribution
        self.expectedBundleId = expectedBundleId
    }
}

/// Verifies app integrity: bundle-identifier match (repackage detection) and
/// distribution provenance (App Store receipt / provisioning profile).
struct IntegrityChecker: Probe {
    let id = "integrity"
    private let env: DeviceEnvironment
    private let policy: IntegrityPolicy

    init(_ env: DeviceEnvironment, policy: IntegrityPolicy) {
        self.env = env
        self.policy = policy
    }

    func evaluate() -> Set<RiskSignal> {
        var signals = Set<RiskSignal>()

        if let expected = policy.expectedBundleId, !expected.isEmpty {
            if env.bundleIdentifier != expected {
                signals.insert(.repackaged)
                signals.insert(.appIntegrity)
            }
        }

        if policy.requireAppStoreDistribution {
            if env.hasEmbeddedMobileProvision || !env.hasAppStoreReceipt {
                signals.insert(.appIntegrity)
            }
        }

        return signals
    }
}
