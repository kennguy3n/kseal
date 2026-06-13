import Foundation
import PackagePlugin

// KsealRegisterPlugin — a command plugin that registers a build proof emitted by
// KsealHardenPlugin with `RegistryService.CreateBuild`. It is network-permitted
// (declared in Package.swift) and always has an offline fallback so it never
// blocks a build.
//
// Usage:
//   swift package --allow-network-connections all kseal-register \
//       [--manifest <path>] [--offline-artifact <path>] [--offline]
//
// Configuration comes from the environment (never flags/files), so the API key
// is never logged or committed:
//   KSEAL_REGISTRY_URL, KSEAL_API_KEY, KSEAL_TENANT_ID, KSEAL_APP_ID,
//   KSEAL_PROTECTION_PROFILE_ID (optional).

@main
struct KsealRegisterPlugin: CommandPlugin {
    private static let manifestName = "kseal-build-proof.json"

    func performCommand(context: PluginContext, arguments: [String]) async throws {
        let tool = try context.tool(named: "kseal-harden")

        // When no explicit --manifest is given, discover the proof the build-tool
        // plugin emitted. Its outputs live under the package build tree
        // (.build/plugins/outputs/.../KsealHardenPlugin/), which is a sibling of
        // this command plugin's work directory — not inside it — so we search the
        // shared `outputs` ancestor and pick the most recently written manifest.
        var forwarded = arguments
        if !arguments.contains("--manifest") {
            guard let discovered = discoverManifest(workDir: context.pluginWorkDirectory) else {
                Diagnostics.error("""
                no \(Self.manifestName) found in the build outputs. Build a target that \
                applies KsealHardenPlugin first, or pass --manifest <path> explicitly.
                """)
                return
            }
            forwarded += ["--manifest", discovered]
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool.path.string)
        process.arguments = ["register"] + forwarded
        try process.run()
        process.waitUntilExit()
        if process.terminationStatus != 0 {
            Diagnostics.error("kseal-register failed with exit code \(process.terminationStatus)")
        }
    }

    /// Walks up from the command plugin's work directory to the shared `plugins`
    /// build root and returns the newest emitted manifest, if any. (The command
    /// plugin's own work dir is itself a `.../plugins/<plugin>/outputs`, so we go
    /// all the way up to `plugins` and search the sibling build-tool outputs.)
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
