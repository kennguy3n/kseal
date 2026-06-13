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
    fail("usage: kseal-harden <generate|register|harden-binary|version> [options]")
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

    let request = HardenRequest(
        targetName: target,
        sdkVersion: opts.value("sdk-version") ?? ksealSDKVersion,
        versionName: opts.value("version-name") ?? "0.0.0",
        versionCode: Int64(opts.value("version-code") ?? "0") ?? 0,
        protectionProfileId: opts.value("protection-profile-id") ?? "",
        secureStrings: secureStrings,
        platform: opts.value("platform") ?? "ios",
        host: opts.value("host") ?? "swiftpm-build-plugin",
        extraToolVersions: toolVersions
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
