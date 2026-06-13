import Foundation

/// Version of the kseal SDK this toolkit hardens against. Kept in sync with
/// `sdk/android/build.gradle.kts` (`version = "0.1.0"`) and the iOS SDK.
public let ksealSDKVersion = "0.1.0"

/// Version of the hardening toolkit itself.
public let ksealHardenVersion = "0.1.0"

/// Parsed declarative input listing the strings a target wants hardened.
///
/// Integrators drop a `kseal-secure-strings.json` next to their sources:
/// `{ "apiBaseURL": "https://api.example.com", "telemetryKey": "…" }`.
/// The plugin replaces these literals with generated, per-build obfuscated
/// accessors (`KsealSecureStrings.apiBaseURL`).
public struct SecureStringsInput {
    public let entries: [String: String]

    public init(entries: [String: String]) { self.entries = entries }

    public static func load(from url: URL) throws -> SecureStringsInput {
        let data = try Data(contentsOf: url)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw HardenEngineError.invalidInput("secure strings file must be a JSON object of identifier → string")
        }
        var entries: [String: String] = [:]
        for (k, v) in obj {
            guard let s = v as? String else {
                throw HardenEngineError.invalidInput("value for \"\(k)\" must be a string")
            }
            entries[k] = s
        }
        return SecureStringsInput(entries: entries)
    }
}

public enum HardenEngineError: Error, CustomStringConvertible {
    case invalidInput(String)

    public var description: String {
        switch self {
        case .invalidInput(let m): return "invalid input: \(m)"
        }
    }
}

/// Inputs describing the build being hardened.
public struct HardenRequest {
    public var targetName: String
    public var sdkVersion: String
    public var versionName: String
    public var versionCode: Int64
    public var protectionProfileId: String
    public var secureStrings: [String: String]
    public var platform: String
    public var host: String
    /// Extra tool versions (e.g. swift, strip) to record in the manifest.
    public var extraToolVersions: [String: String]

    public init(
        targetName: String,
        sdkVersion: String = ksealSDKVersion,
        versionName: String = "0.0.0",
        versionCode: Int64 = 0,
        protectionProfileId: String = "",
        secureStrings: [String: String] = [:],
        platform: String = "ios",
        host: String = "swiftpm-build-plugin",
        extraToolVersions: [String: String] = [:]
    ) {
        self.targetName = targetName
        self.sdkVersion = sdkVersion
        self.versionName = versionName
        self.versionCode = versionCode
        self.protectionProfileId = protectionProfileId
        self.secureStrings = secureStrings
        self.platform = platform
        self.host = host
        self.extraToolVersions = extraToolVersions
    }
}

/// The artifacts produced by a hardening pass.
public struct HardenOutput {
    public let generatedSwiftSource: String
    public let manifest: BuildProofManifest
}

/// Orchestrates a build-time hardening pass: harden flagged strings, derive the
/// per-build polymorphism material, compute the build hash, and assemble the
/// build-proof manifest. Pure and deterministic given its inputs (seed + clock),
/// so it is fully unit-testable without any Apple toolchain.
public struct HardenEngine {
    private let stringHardener: StringHardener
    private let clock: () -> Date

    public init(stringHardener: StringHardener = StringHardener(), clock: @escaping () -> Date = { Date() }) {
        self.stringHardener = stringHardener
        self.clock = clock
    }

    public func run(_ request: HardenRequest, seed: PolymorphismSeed) throws -> HardenOutput {
        let hardened = stringHardener.harden(entries: request.secureStrings, seed: seed)
        let enumName = "KsealSecureStrings"
        let generated = stringHardener.generateSwiftSource(hardened, enumName: enumName)

        var transforms: [BuildProofManifest.Transform] = []
        transforms.append(
            BuildProofManifest.Transform(
                kind: "string-obfuscation",
                algorithm: "seed-xor/sha256-ctr",
                count: hardened.count,
                detail: ["enum": enumName]
            )
        )

        var toolVersions: [String: String] = [
            "ksealHarden": ksealHardenVersion,
        ]
        for (k, v) in request.extraToolVersions { toolVersions[k] = v }

        let modules = ["string-hardening", "polymorphism", "build-proof"]

        let buildHash = computeBuildHash(
            request: request,
            seed: seed,
            generatedSource: generated,
            toolVersions: toolVersions
        )

        let manifest = BuildProofManifest(
            platform: request.platform,
            sdkVersion: request.sdkVersion,
            buildHash: buildHash,
            versionName: request.versionName,
            versionCode: request.versionCode,
            protectionProfileId: request.protectionProfileId,
            polymorphism: .init(seedDigest: seed.digestHex),
            toolVersions: toolVersions,
            transforms: transforms,
            modules: modules,
            provenance: .init(
                generatedAt: Self.rfc3339(clock()),
                generator: "kseal-harden/\(ksealHardenVersion)",
                host: request.host
            )
        )

        return HardenOutput(generatedSwiftSource: generated, manifest: manifest)
    }

    /// Build hash binds the proof to the actual hardened output plus the build's
    /// identity and toolchain — change any input and the hash changes.
    private func computeBuildHash(
        request: HardenRequest,
        seed: PolymorphismSeed,
        generatedSource: String,
        toolVersions: [String: String]
    ) -> String {
        var material = [UInt8]()
        func add(_ s: String) { material.append(contentsOf: Array(s.utf8)); material.append(0x1f) }
        add("kseal-build-hash/v1")
        add(request.platform)
        add(request.sdkVersion)
        add(request.targetName)
        add(request.versionName)
        add(String(request.versionCode))
        add(request.protectionProfileId)
        add(seed.digestHex)
        for key in toolVersions.keys.sorted() { add(key); add(toolVersions[key] ?? "") }
        add(generatedSource)
        return SHA256.hexDigest(material)
    }

    /// RFC 3339 / ISO 8601 UTC timestamp, second precision.
    public static func rfc3339(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return formatter.string(from: date)
    }
}
