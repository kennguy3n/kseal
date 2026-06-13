import Foundation

/// The canonical kseal **build-proof manifest**.
///
/// One schema is shared by every build plane (iOS here; Android/Gradle — WS-B —
/// emits the same shape) so the control plane and the runtime build-proof check
/// can validate a build regardless of platform. It is serialized to JSON and
/// carried in `RegistryService.CreateBuild`'s `manifest` field (the proto
/// documents it as "provenance, module set, transforms applied"); the
/// `buildHash` is sent as the request's `build_hash`.
///
/// Versioning: `schemaVersion` is bumped only on incompatible changes; additive
/// fields keep the same major. Both plugins must agree on `schemaVersion`.
public struct BuildProofManifest: Codable, Equatable {
    public static let currentSchemaVersion = "1.0"

    /// Manifest schema version (e.g. "1.0").
    public var schemaVersion: String
    /// Build plane platform: "ios" or "android".
    public var platform: String
    /// kseal SDK version embedded in the protected build.
    public var sdkVersion: String
    /// Content hash of the protected build (also sent as `CreateBuild.build_hash`).
    public var buildHash: String
    /// Marketing version (CFBundleShortVersionString / versionName).
    public var versionName: String
    /// Build number (CFBundleVersion / versionCode).
    public var versionCode: Int64
    /// Protection profile id this build was hardened against (optional).
    public var protectionProfileId: String
    /// Per-build polymorphism summary (digest only — never the raw seed).
    public var polymorphism: Polymorphism
    /// Versions of every tool that touched the build, for reproducibility/audit.
    public var toolVersions: [String: String]
    /// Hardening transforms applied, in application order.
    public var transforms: [Transform]
    /// Enabled hardening modules (stable identifiers).
    public var modules: [String]
    /// Build provenance.
    public var provenance: Provenance

    public struct Polymorphism: Codable, Equatable {
        /// SHA-256 of the per-build seed, hex encoded.
        public var seedDigest: String
        /// Keystream algorithm used to derive transform material from the seed.
        public var algorithm: String

        public init(seedDigest: String, algorithm: String = "sha256-ctr") {
            self.seedDigest = seedDigest
            self.algorithm = algorithm
        }
    }

    public struct Transform: Codable, Equatable {
        /// Transform kind, e.g. "string-obfuscation", "symbol-strip".
        public var kind: String
        /// Algorithm / tool identifier for the transform.
        public var algorithm: String
        /// Number of items affected (strings hardened, symbols removed, …).
        public var count: Int
        /// Optional free-form detail (tool flags, etc.).
        public var detail: [String: String]?

        public init(kind: String, algorithm: String, count: Int, detail: [String: String]? = nil) {
            self.kind = kind
            self.algorithm = algorithm
            self.count = count
            self.detail = detail
        }
    }

    public struct Provenance: Codable, Equatable {
        /// RFC 3339 UTC timestamp the manifest was generated.
        public var generatedAt: String
        /// Generator identifier, e.g. "kseal-harden/0.1.0".
        public var generator: String
        /// Logical build host/context, e.g. "swiftpm-build-plugin".
        public var host: String

        public init(generatedAt: String, generator: String, host: String) {
            self.generatedAt = generatedAt
            self.generator = generator
            self.host = host
        }
    }

    public init(
        schemaVersion: String = currentSchemaVersion,
        platform: String = "ios",
        sdkVersion: String,
        buildHash: String,
        versionName: String,
        versionCode: Int64,
        protectionProfileId: String = "",
        polymorphism: Polymorphism,
        toolVersions: [String: String],
        transforms: [Transform],
        modules: [String],
        provenance: Provenance
    ) {
        self.schemaVersion = schemaVersion
        self.platform = platform
        self.sdkVersion = sdkVersion
        self.buildHash = buildHash
        self.versionName = versionName
        self.versionCode = versionCode
        self.protectionProfileId = protectionProfileId
        self.polymorphism = polymorphism
        self.toolVersions = toolVersions
        self.transforms = transforms
        self.modules = modules
        self.provenance = provenance
    }

    /// Deterministic, stable JSON (sorted keys, no escaping of slashes) suitable
    /// for hashing and for the `CreateBuild.manifest` field.
    public func jsonString() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(self)
        return String(decoding: data, as: UTF8.self)
    }

    public func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    public static func decode(from data: Data) throws -> BuildProofManifest {
        try JSONDecoder().decode(BuildProofManifest.self, from: data)
    }
}
