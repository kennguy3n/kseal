import Foundation
import PackagePlugin

// KsealMasvsReportPlugin — an optional command plugin that generates a per-release
// MASVS evidence report from the build proof emitted by KsealHardenPlugin.
//
// It is a thin launcher: all report logic lives in the standalone, fully-tested
// `masvs-report` generator (tools/masvs-report). The plugin discovers the
// manifest the build-tool plugin wrote (the same document registered via
// RegistryService.CreateBuild), then runs the generator against the MASVS
// control catalog (docs/masvs-mapping.md).
//
// Usage:
//   swift package --allow-writing-to-package-directory kseal-masvs-report \
//       [--manifest <path>] [--catalog <path>] [--generator <path>] [--out-dir <dir>]
//
// The generator binary is resolved, in order, from: --generator, the
// KSEAL_MASVS_GENERATOR environment variable, or a `masvs-report` tool on PATH.
// The catalog defaults to KSEAL_MASVS_CATALOG or docs/masvs-mapping.md.

@main
struct KsealMasvsReportPlugin: CommandPlugin {
    private static let manifestName = "kseal-build-proof.json"

    func performCommand(context: PluginContext, arguments: [String]) async throws {
        let opts = Options(arguments: arguments)
        let env = ProcessInfo.processInfo.environment

        guard let manifest = opts.manifest ?? discoverManifest(workDir: context.pluginWorkDirectory) else {
            Diagnostics.error("""
            no \(Self.manifestName) found in the build outputs. Build a target that \
            applies KsealHardenPlugin first, or pass --manifest <path> explicitly.
            """)
            return
        }

        guard let generator = resolveGenerator(opts: opts, env: env, context: context) else {
            Diagnostics.error("""
            masvs-report generator not found. Build tools/masvs-report and pass its \
            path via --generator <path> or the KSEAL_MASVS_GENERATOR environment variable.
            """)
            return
        }

        let catalog = opts.catalog ?? env["KSEAL_MASVS_CATALOG"] ?? "docs/masvs-mapping.md"
        let outDir = opts.outDir ?? URL(fileURLWithPath: manifest).deletingLastPathComponent().path
        let md = outDir + "/masvs-evidence.md"
        let json = outDir + "/masvs-evidence.json"

        let process = Process()
        process.executableURL = URL(fileURLWithPath: generator)
        process.arguments = [
            "-manifest", manifest,
            "-catalog", catalog,
            "-out-md", md,
            "-out-json", json,
        ]
        try process.run()
        process.waitUntilExit()
        if process.terminationStatus != 0 {
            Diagnostics.error("masvs-report failed with exit code \(process.terminationStatus)")
            return
        }
        print("kseal: MASVS evidence report written to \(md)")
    }

    private func resolveGenerator(opts: Options, env: [String: String], context: PluginContext) -> String? {
        if let explicit = opts.generator, !explicit.isEmpty { return explicit }
        if let fromEnv = env["KSEAL_MASVS_GENERATOR"], !fromEnv.isEmpty { return fromEnv }
        return try? context.tool(named: "masvs-report").path.string
    }

    /// Walks up from the command plugin's work directory to the shared `plugins`
    /// build root and returns the newest emitted manifest, if any (identical
    /// discovery to KsealRegisterPlugin).
    private func discoverManifest(workDir: Path) -> String? {
        let fm = FileManager.default
        var searchRoot = URL(fileURLWithPath: workDir.string)
        while searchRoot.lastPathComponent != "plugins", searchRoot.pathComponents.count > 1 {
            searchRoot.deleteLastPathComponent()
        }
        let root = searchRoot.lastPathComponent == "plugins"
            ? searchRoot
            : URL(fileURLWithPath: workDir.string)

        guard let enumerator = fm.enumerator(at: root, includingPropertiesForKeys: [.contentModificationDateKey]) else {
            return nil
        }
        var newest: (url: URL, date: Date)?
        for case let url as URL in enumerator where url.lastPathComponent == Self.manifestName {
            let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            if newest == nil || date > newest!.date {
                newest = (url, date)
            }
        }
        return newest?.url.path
    }
}

/// Parsed `--flag value` options. Unknown flags are ignored so the plugin stays
/// forward-compatible with the generator's own flags.
private struct Options {
    var manifest: String?
    var catalog: String?
    var generator: String?
    var outDir: String?

    init(arguments: [String]) {
        var i = 0
        while i < arguments.count {
            let arg = arguments[i]
            let value: String? = i + 1 < arguments.count ? arguments[i + 1] : nil
            switch arg {
            case "--manifest": manifest = value; i += 2
            case "--catalog": catalog = value; i += 2
            case "--generator": generator = value; i += 2
            case "--out-dir": outDir = value; i += 2
            default: i += 1
            }
        }
    }
}
