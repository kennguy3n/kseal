import Foundation
import KsealHardenCore

// kseal-harden — the build-tool executable invoked by the SwiftPM/Xcode plugins
// and by CI. Subcommands:
//
//   generate       Harden flagged strings + emit the build-proof manifest.
//                  (Run by the build-tool plugin; no network.)
//   register       Register an emitted manifest with RegistryService.CreateBuild,
//                  with an offline artifact fallback. (Run by the command plugin
//                  or CI; network-permitted.)
//   harden-binary  Strip symbols/metadata from a linked binary (strip/nm/otool).
//   integrity      Compute Mach-O section-hash integrity for a linked binary and
//                  bake it into an emitted manifest. (Run post-link by a run-script
//                  phase or CI; pure file parsing, no network.)
//   version        Print the toolkit version.
//
// All output is line-oriented and never contains secrets (no seed, no API key).

let arguments = Array(CommandLine.arguments.dropFirst())

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("kseal-harden: " + message + "\n").utf8))
    exit(2)
}

func note(_ message: String) {
    FileHandle.standardError.write(Data(("kseal-harden: " + message + "\n").utf8))
}

/// Tiny flag parser: `--key value` and repeatable `--tool-version k=v`.
struct Args {
    private var values: [String: [String]] = [:]
    private var flags: Set<String> = []

    init(_ raw: [String]) {
        var i = 0
        while i < raw.count {
            let token = raw[i]
            if token.hasPrefix("--") {
                let key = String(token.dropFirst(2))
                if i + 1 < raw.count, !raw[i + 1].hasPrefix("--") {
                    values[key, default: []].append(raw[i + 1])
                    i += 2
                } else {
                    flags.insert(key)
                    i += 1
                }
            } else {
                i += 1
            }
        }
    }

    func value(_ key: String) -> String? { values[key]?.first }
    func values(_ key: String) -> [String] { values[key] ?? [] }
    func flag(_ key: String) -> Bool { flags.contains(key) }
    func require(_ key: String) -> String {
        guard let v = value(key) else { fail("missing required --\(key)") }
        return v
    }
}

guard let command = arguments.first else {
    fail("usage: kseal-harden <generate|register|harden-binary|integrity|version> [options]")
}
let opts = Args(Array(arguments.dropFirst()))

switch command {
case "version":
    print("kseal-harden \(ksealHardenVersion) (sdk \(ksealSDKVersion))")

case "generate":
    runGenerate(opts)

case "register":
    runRegister(opts)

case "harden-binary":
    runHardenBinary(opts)

case "integrity":
    runIntegrity(opts)

default:
    fail("unknown command \"\(command)\"")
}

func runGenerate(_ opts: Args) {
    let target = opts.require("target")
    let outStrings = URL(fileURLWithPath: opts.require("out-strings"))
    let outManifest = URL(fileURLWithPath: opts.require("out-manifest"))

    var secureStrings: [String: String] = [:]
    if let file = opts.value("secure-strings") {
        let url = URL(fileURLWithPath: file)
        if FileManager.default.fileExists(atPath: url.path) {
            do {
                secureStrings = try SecureStringsInput.load(from: url).entries
            } catch {
                fail("\(error)")
            }
        }
    }

    var toolVersions: [String: String] = [:]
    for pair in opts.values("tool-version") {
        // Keep empty subsequences so "swift=" records an empty version rather
        // than being silently dropped; only require a non-empty tool name.
        let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        if parts.count == 2, !parts[0].isEmpty { toolVersions[String(parts[0])] = String(parts[1]) }
    }

    // Determine how the seed will be sourced so the manifest's reproducibility
    // posture is honest (mirrors PolymorphismSeed.resolve precedence).
    //
    // A seed that is *explicitly supplied but invalid* must fail loudly: silently
    // falling back to a random seed would turn a build the operator pinned for
    // reproducibility into a non-reproducible one without warning.
    let cliSeed = opts.value("build-seed")
    let envSeed = ProcessInfo.processInfo.environment["KSEAL_BUILD_SEED"]?
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let seedDerivation: String
    if let h = cliSeed {
        guard PolymorphismSeed(hex: h) != nil else {
            fail("--build-seed must be hex-encoded and decode to at least 16 bytes " +
                 "(generate one with `openssl rand -hex 32`).")
        }
        seedDerivation = "explicit"
    } else if let h = envSeed, !h.isEmpty {
        guard PolymorphismSeed(hex: h) != nil else {
            fail("KSEAL_BUILD_SEED must be hex-encoded and decode to at least 16 bytes " +
                 "(generate one with `openssl rand -hex 32`), or unset it for a random seed.")
        }
        seedDerivation = "env"
    } else {
        seedDerivation = "random"
    }

    let request = HardenRequest(
        targetName: target,
        sdkVersion: opts.value("sdk-version") ?? ksealSDKVersion,
        versionName: opts.value("version-name") ?? "0.0.0",
        versionCode: Int64(opts.value("version-code") ?? "0") ?? 0,
        protectionProfileId: opts.value("protection-profile-id") ?? "",
        secureStrings: secureStrings,
        platform: opts.value("platform") ?? "ios",
        host: opts.value("host") ?? "swiftpm-build-plugin",
        extraToolVersions: toolVersions,
        seedDerivation: seedDerivation
    )

    let seed = PolymorphismSeed.resolve(explicitHex: opts.value("build-seed"))
    do {
        let output = try HardenEngine().run(request, seed: seed)
        try FileManager.default.createDirectory(at: outStrings.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outManifest.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(output.generatedSwiftSource.utf8).write(to: outStrings, options: .atomic)
        try output.manifest.jsonData().write(to: outManifest, options: .atomic)
        note("hardened \(request.secureStrings.count) string(s) for target \"\(target)\"; build hash \(output.manifest.buildHash.prefix(12))…")
    } catch {
        fail("\(error)")
    }
}

func runRegister(_ opts: Args) {
    let manifestURL = URL(fileURLWithPath: opts.require("manifest"))
    let artifactURL = URL(fileURLWithPath: opts.value("offline-artifact")
        ?? manifestURL.deletingLastPathComponent().appendingPathComponent("kseal-build-proof.offline.json").path)

    let manifest: BuildProofManifest
    do {
        manifest = try BuildProofManifest.decode(from: Data(contentsOf: manifestURL))
    } catch {
        fail("could not read manifest: \(error)")
    }

    let config = RegistryConfig.fromEnvironment()
    if config == nil {
        note("registry not configured (set KSEAL_REGISTRY_URL/KSEAL_API_KEY/KSEAL_TENANT_ID/KSEAL_APP_ID); writing offline proof")
    }

    let registrar = BuildProofRegistrar()
    let result = registrar.register(
        manifest: manifest,
        config: config,
        offlineArtifact: artifactURL,
        forceOffline: opts.flag("offline")
    )
    switch result {
    case .success(.registered(let id)):
        print("registered build \(id) (hash \(manifest.buildHash.prefix(12))…)")
    case .success(.offline(let path)):
        print("offline build proof written to \(path) (hash \(manifest.buildHash.prefix(12))…)")
    case .failure(let error):
        fail("registration failed and offline write failed: \(error)")
    }
}

func runIntegrity(_ opts: Args) {
    let binary = URL(fileURLWithPath: opts.require("binary"))
    let manifestURL = URL(fileURLWithPath: opts.require("manifest"))
    let outURL = URL(fileURLWithPath: opts.value("out-manifest") ?? manifestURL.path)

    var manifest: BuildProofManifest
    do {
        manifest = try BuildProofManifest.decode(from: Data(contentsOf: manifestURL))
    } catch {
        fail("could not read manifest: \(error)")
    }

    let integrity: BuildProofManifest.Integrity
    let posture: MachOInspector.Posture
    let stringObfuscation: MachOInspector.StringObfuscation
    do {
        let inspector = MachOInspector()
        integrity = try inspector.inspect(binaryAt: binary)
        posture = try inspector.posture(binaryAt: binary)
        stringObfuscation = try inspector.stringObfuscation(binaryAt: binary)
    } catch {
        fail("\(error)")
    }

    let sectionCount = integrity.slices.reduce(0) { $0 + $1.sections.count }
    manifest.integrity = integrity
    manifest.posture = posture
    manifest.hashCoverage = BuildProofManifest.HashCoverage.from(integrity: integrity)
    // Enriching an existing manifest brings it up to the current revision.
    manifest.manifestRevision = BuildProofManifest.currentManifestRevision
    // Record the transforms idempotently so re-running doesn't duplicate them.
    manifest.transforms.removeAll {
        $0.kind == "macho-section-integrity"
            || $0.kind == "macho-binary-posture"
            || $0.kind == "macho-string-obfuscation"
    }
    manifest.transforms.append(
        BuildProofManifest.Transform(
            kind: "macho-section-integrity",
            algorithm: "sha256",
            count: sectionCount,
            detail: ["slices": String(integrity.slices.count), "format": integrity.format]
        )
    )
    let findings = posture.slices.reduce(0) { acc, s in acc + (s.hardened ? 0 : 1) }
    manifest.transforms.append(
        BuildProofManifest.Transform(
            kind: "macho-binary-posture",
            algorithm: "macho-parse",
            count: posture.slices.count,
            detail: ["all_hardened": String(posture.allHardened), "slices_with_findings": String(findings)]
        )
    )
    manifest.transforms.append(
        BuildProofManifest.Transform(
            kind: "macho-string-obfuscation",
            algorithm: "ascii-scan",
            count: stringObfuscation.markersFound.count,
            detail: [
                "status": stringObfuscation.status.rawValue,
                "kseal_core": String(stringObfuscation.isKsealCore),
                "markers_found": stringObfuscation.markersFound.joined(separator: ","),
            ]
        )
    )
    for module in ["macho-section-integrity", "macho-binary-posture", "macho-string-obfuscation"]
    where !manifest.modules.contains(module) {
        manifest.modules = (manifest.modules + [module]).sorted()
    }

    do {
        try manifest.jsonData().write(to: outURL, options: .atomic)
    } catch {
        fail("could not write manifest: \(error)")
    }
    let archs = integrity.slices.map { $0.arch }.joined(separator: ",")
    let postureSummary = posture.allHardened ? "all slices hardened" : "\(findings) slice(s) with findings"
    print("baked Mach-O integrity for \(binary.lastPathComponent): \(integrity.slices.count) slice(s) [\(archs)], \(sectionCount) section hash(es); posture: \(postureSummary); string-obfuscation: \(stringObfuscation.status.rawValue)")
}

func runHardenBinary(_ opts: Args) {
    let binary = URL(fileURLWithPath: opts.require("binary"))
    let env = ToolEnvironment.detect()
    guard env.strip != nil else {
        note("`strip` unavailable on this host; skipping symbol stripping")
        exit(0)
    }
    let hardener = SymbolHardener()
    do {
        let result = try hardener.strip(binary: binary, env: env)
        print("stripped \(binary.lastPathComponent): \(result.symbolsBefore) → \(result.symbolsAfter) symbols (removed \(result.removedSymbols))")
    } catch {
        fail("\(error)")
    }
}
