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
    func performCommand(context: PluginContext, arguments: [String]) async throws {
        let tool = try context.tool(named: "kseal-harden")

        // Default to the manifest the build-tool plugin emits for the package's
        // first source target when no explicit --manifest is provided.
        var forwarded = arguments
        if !arguments.contains("--manifest") {
            let fallback = context.pluginWorkDirectory.appending("kseal-build-proof.json")
            forwarded += ["--manifest", fallback.string]
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
}
