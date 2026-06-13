import Foundation
#if canImport(CoreFoundation)
import CoreFoundation
#endif

/// Telemetry detail the host is asked to honor.
public enum TelemetryVerbosity: String, Sendable, Codable {
    /// Only events that carry at least one risk signal are recorded.
    case minimal
    /// Default: every event the host reports is recorded.
    case standard
    /// Standard plus any additional diagnostics the host opts into.
    case verbose
}

/// MDM-friendly enterprise compatibility controls the desktop SDK reads from a
/// **managed configuration** (macOS managed preferences / config profile;
/// see `docs/desktop-sdk.md`).
///
/// Every default is **strict**: an unconfigured policy (`.strict`) relaxes
/// nothing and produces byte-for-byte the same behavior the SDK had before this
/// control existed. Controls are therefore opt-in, and the effective policy is
/// surfaced (`KsealDesktop.enterprisePolicy`) so a deployment can audit exactly
/// what was relaxed.
public struct EnterprisePolicy: Equatable, Sendable, Codable {
    /// Suppress the (opt-in) debugger probe — for managed developer machines
    /// where debugging is legitimate. Strict default: false (no suppression).
    public var permitDebugger: Bool
    /// Module paths (exact match or directory prefix ending in `/`) that are
    /// legitimate plugins/agents and must not raise the injection signal.
    public var injectionAllowlist: [String]
    /// Telemetry detail the host should honor. Strict default: `.standard`.
    public var telemetryVerbosity: TelemetryVerbosity
    /// When true, a request-proof key that is **not** hardware-backed raises the
    /// `secureHwMissing` signal (fail closed for a regulated tier). Strict
    /// default: false.
    public var requireHardwareBackedProofKey: Bool

    public init(
        permitDebugger: Bool = false,
        injectionAllowlist: [String] = [],
        telemetryVerbosity: TelemetryVerbosity = .standard,
        requireHardwareBackedProofKey: Bool = false
    ) {
        self.permitDebugger = permitDebugger
        self.injectionAllowlist = injectionAllowlist
        self.telemetryVerbosity = telemetryVerbosity
        self.requireHardwareBackedProofKey = requireHardwareBackedProofKey
    }

    /// The strict baseline: identical to the SDK's behavior with no managed
    /// configuration present.
    public static let strict = EnterprisePolicy()

    /// Whether this policy relaxes nothing relative to the strict baseline.
    public var isStrict: Bool { self == .strict }

    enum CodingKeys: String, CodingKey {
        case permitDebugger
        case injectionAllowlist
        case telemetryVerbosity
        case requireHardwareBackedProofKey
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Missing keys fall back to the strict default, so a partial managed
        // config only relaxes the keys it explicitly sets.
        permitDebugger = try c.decodeIfPresent(Bool.self, forKey: .permitDebugger) ?? false
        injectionAllowlist = try c.decodeIfPresent([String].self, forKey: .injectionAllowlist) ?? []
        telemetryVerbosity = try c.decodeIfPresent(TelemetryVerbosity.self, forKey: .telemetryVerbosity) ?? .standard
        requireHardwareBackedProofKey =
            try c.decodeIfPresent(Bool.self, forKey: .requireHardwareBackedProofKey) ?? false
    }

    /// Whether a foreign module `path` is allowlisted (exact match, or under an
    /// allowlist entry that names a directory prefix ending in `/`).
    public func allowsModule(_ path: String) -> Bool {
        // Fail closed on a path that could escape an allowlisted prefix via a
        // parent-directory segment (e.g. /Library/Acme/../evil.dylib).
        if Self.hasParentTraversal(path) { return false }
        for entry in injectionAllowlist where !entry.isEmpty {
            if entry.hasSuffix("/") {
                if path.hasPrefix(entry) { return true }
            } else if path == entry {
                return true
            }
        }
        return false
    }

    /// True if any path segment (split on either separator) is exactly `..`.
    private static func hasParentTraversal(_ path: String) -> Bool {
        path.split(whereSeparator: { $0 == "/" || $0 == "\\" }).contains("..")
    }
}

/// Source of the effective `EnterprisePolicy`. Production reads the OS-managed
/// configuration; tests and hosts can inject a fixed policy.
public protocol EnterprisePolicyProvider {
    func currentPolicy() -> EnterprisePolicy
}

/// Always returns a fixed policy (default: strict). Used when a host supplies a
/// policy directly and as the safe fallback when no managed config is present.
public struct StaticEnterprisePolicyProvider: EnterprisePolicyProvider {
    private let policy: EnterprisePolicy
    public init(_ policy: EnterprisePolicy = .strict) { self.policy = policy }
    public func currentPolicy() -> EnterprisePolicy { policy }
}

/// Reads the policy from a JSON file (the documented MDM drop path on hosts
/// without a managed-preferences API, and the deterministic seam for tests).
/// A missing or malformed file yields the strict baseline (fail safe).
public struct FileEnterprisePolicyProvider: EnterprisePolicyProvider {
    private let url: URL
    public init(url: URL) { self.url = url }

    public func currentPolicy() -> EnterprisePolicy {
        guard let data = try? Data(contentsOf: url),
              let policy = try? JSONDecoder().decode(EnterprisePolicy.self, from: data) else {
            return .strict
        }
        return policy
    }
}

/// The managed-preferences domain the SDK reads enterprise controls from.
let enterprisePolicyDomain = "io.kseal.desktop"

#if canImport(CoreFoundation) && canImport(Darwin)
/// Reads enterprise controls from **managed preferences** — the values an MDM
/// delivers via a configuration profile for `io.kseal.desktop`. Uses only the
/// public `CFPreferences` API; unset keys keep the strict default.
public struct ManagedPreferencesPolicyProvider: EnterprisePolicyProvider {
    private let domain: String
    public init(domain: String = enterprisePolicyDomain) { self.domain = domain }

    public func currentPolicy() -> EnterprisePolicy {
        let cfDomain = domain as CFString
        var policy = EnterprisePolicy.strict

        // CFBoolean bridges to Swift Bool; a mistyped pref simply keeps the
        // strict default rather than relaxing the control.
        if let value = CFPreferencesCopyAppValue("PermitDebugger" as CFString, cfDomain) as? Bool {
            policy.permitDebugger = value
        }
        if let value = CFPreferencesCopyAppValue("RequireHardwareBackedProofKey" as CFString, cfDomain) as? Bool {
            policy.requireHardwareBackedProofKey = value
        }
        if let value = CFPreferencesCopyAppValue("InjectionAllowlist" as CFString, cfDomain) as? [String] {
            policy.injectionAllowlist = value
        }
        if let value = CFPreferencesCopyAppValue("TelemetryVerbosity" as CFString, cfDomain) as? String,
           let verbosity = TelemetryVerbosity(rawValue: value) {
            policy.telemetryVerbosity = verbosity
        }
        return policy
    }
}
#endif

/// Returns the production enterprise-policy provider for the current platform.
func makeDefaultEnterprisePolicyProvider() -> EnterprisePolicyProvider {
    #if canImport(CoreFoundation) && canImport(Darwin)
    return ManagedPreferencesPolicyProvider()
    #else
    // Non-Apple host: read the documented JSON drop path if present, else strict.
    return FileEnterprisePolicyProvider(
        url: URL(fileURLWithPath: "/etc/kseal/desktop-enterprise-policy.json"))
    #endif
}
