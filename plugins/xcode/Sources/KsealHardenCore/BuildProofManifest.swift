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

    /// Additive content revision within `currentSchemaVersion`. Bumped to 2 when
    /// reproducibility / hash-coverage / posture sections were added.
    public static let currentManifestRevision = 2

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
    /// Optional binary-integrity evidence (Mach-O section/load-command hashes)
    /// the runtime uses to detect post-build tampering. Additive: absent in
    /// builds produced before integrity baking (and on the Android plane).
    public var integrity: Integrity?

    // --- Manifest revision 2 additive fields (same `schemaVersion`) ----------
    // All optional so manifests written before revision 2 still decode cleanly.

    /// Additive content revision within the current `schemaVersion`. Bumped to 2
    /// when reproducibility / hash-coverage / posture were added; the schema
    /// version is unchanged so existing consumers keep validating.
    public var manifestRevision: Int?
    /// Reproducibility posture (whether the build is deterministically rebuildable).
    public var reproducibility: Reproducibility?
    /// Explicit description of what the build hash / integrity evidence covers.
    public var hashCoverage: HashCoverage?
    /// Per-binary exploit-mitigation posture (PIE/NX/canary/FORTIFY/…), parsed
    /// from the linked Mach-O. Populated post-link alongside `integrity`.
    public var posture: MachOInspector.Posture?

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

    /// Mach-O binary-integrity evidence: per-architecture-slice section hashes
    /// plus load-command validation data. Computed from the *linked* binary
    /// (post-link) so the runtime can recompute and compare to detect tampering.
    public struct Integrity: Codable, Equatable {
        /// Binary format the evidence describes (currently always "macho").
        public var format: String
        /// One entry per architecture slice (>1 for a universal/fat binary).
        public var slices: [Slice]

        public init(format: String = "macho", slices: [Slice]) {
            self.format = format
            self.slices = slices
        }

        public struct Slice: Codable, Equatable {
            /// Architecture name, e.g. "arm64", "x86_64".
            public var arch: String
            /// Mach-O file type, e.g. "execute", "dylib".
            public var fileType: String
            /// True when the slice is position-independent (MH_PIE).
            public var pie: Bool
            /// True when the slice carries Apple FairPlay encryption (cryptid != 0).
            public var encrypted: Bool
            /// LC_UUID value, hex (empty when the binary carries no UUID).
            public var uuid: String
            /// Number of load commands (ncmds).
            public var loadCommandCount: Int
            /// Total size of the load-command region (sizeofcmds).
            public var loadCommandsSize: Int
            /// SHA-256 over the entire load-command region, hex.
            public var loadCommandsHash: String
            /// Per-section content hashes, sorted by segment+section.
            public var sections: [SectionHash]

            public init(
                arch: String,
                fileType: String,
                pie: Bool,
                encrypted: Bool,
                uuid: String,
                loadCommandCount: Int,
                loadCommandsSize: Int,
                loadCommandsHash: String,
                sections: [SectionHash]
            ) {
                self.arch = arch
                self.fileType = fileType
                self.pie = pie
                self.encrypted = encrypted
                self.uuid = uuid
                self.loadCommandCount = loadCommandCount
                self.loadCommandsSize = loadCommandsSize
                self.loadCommandsHash = loadCommandsHash
                self.sections = sections
            }
        }

        public struct SectionHash: Codable, Equatable {
            public var segment: String
            public var section: String
            public var size: Int
            /// SHA-256 over the section's file bytes, hex. Empty for zero-fill
            /// (`S_ZEROFILL`/`bss`) sections that occupy no file range.
            public var hash: String

            public init(segment: String, section: String, size: Int, hash: String) {
                self.segment = segment
                self.section = section
                self.size = size
                self.hash = hash
            }
        }
    }

    /// Whether the build is byte-for-byte reproducible from identical inputs.
    public struct Reproducibility: Codable, Equatable {
        /// True when the build can be deterministically reproduced. On iOS this
        /// requires a pinned seed (`KSEAL_BUILD_SEED`/`--build-seed`); a default
        /// random seed makes the build intentionally non-reproducible.
        public var reproducible: Bool
        /// How the per-build seed was obtained: "explicit", "env" or "random".
        public var seedDerivation: String
        /// Algorithm used to compute the build hash.
        public var buildHashAlgorithm: String

        public init(reproducible: Bool, seedDerivation: String, buildHashAlgorithm: String = "sha256") {
            self.reproducible = reproducible
            self.seedDerivation = seedDerivation
            self.buildHashAlgorithm = buildHashAlgorithm
        }
    }

    /// Auditable description of exactly what the integrity evidence covers, with
    /// an independently recomputable root over the section hashes.
    public struct HashCoverage: Codable, Equatable {
        public var algorithm: String
        public var sliceCount: Int
        public var sectionCount: Int
        /// Total file bytes covered by section hashes (zero-fill sections excluded).
        public var bytesCovered: Int
        /// SHA-256 over the sorted `arch\u{1f}segment\u{1f}section\u{1f}hash` lines
        /// (plus each slice's load-command hash), so a verifier can confirm the
        /// manifest covers precisely this binary without trusting the build host.
        public var artifactsRoot: String
        public var complete: Bool

        public init(
            algorithm: String = "sha256",
            sliceCount: Int,
            sectionCount: Int,
            bytesCovered: Int,
            artifactsRoot: String,
            complete: Bool
        ) {
            self.algorithm = algorithm
            self.sliceCount = sliceCount
            self.sectionCount = sectionCount
            self.bytesCovered = bytesCovered
            self.artifactsRoot = artifactsRoot
            self.complete = complete
        }

        /// Derives the coverage summary from parsed Mach-O integrity evidence.
        public static func from(integrity: Integrity) -> HashCoverage {
            var lines: [String] = []
            var sectionCount = 0
            var bytesCovered = 0
            for slice in integrity.slices.sorted(by: { $0.arch < $1.arch }) {
                lines.append("\(slice.arch)\u{1f}__loadcommands\u{1f}\u{1f}\(slice.loadCommandsHash)")
                for section in slice.sections.sorted(by: { ($0.segment, $0.section) < ($1.segment, $1.section) }) {
                    sectionCount += 1
                    if !section.hash.isEmpty {
                        bytesCovered += section.size
                        lines.append("\(slice.arch)\u{1f}\(section.segment)\u{1f}\(section.section)\u{1f}\(section.hash)")
                    }
                }
            }
            let root = SHA256.hexDigest(Array(lines.joined(separator: "\n").utf8))
            return HashCoverage(
                sliceCount: integrity.slices.count,
                sectionCount: sectionCount,
                bytesCovered: bytesCovered,
                artifactsRoot: root,
                complete: !integrity.slices.isEmpty
            )
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
        provenance: Provenance,
        integrity: Integrity? = nil,
        manifestRevision: Int? = currentManifestRevision,
        reproducibility: Reproducibility? = nil,
        hashCoverage: HashCoverage? = nil,
        posture: MachOInspector.Posture? = nil
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
        self.integrity = integrity
        self.manifestRevision = manifestRevision
        self.reproducibility = reproducibility
        self.hashCoverage = hashCoverage
        self.posture = posture
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
