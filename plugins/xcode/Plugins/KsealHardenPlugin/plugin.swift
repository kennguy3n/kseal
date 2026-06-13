import Foundation
import PackagePlugin

// KsealHardenPlugin — a SwiftPM/Xcode **build-tool plugin** that runs kseal
// build-time hardening for a target:
//
//   * Generates a per-build obfuscated string table compiled into the target.
//   * Emits the build-proof manifest (build hash, seed digest, tool versions,
//     SDK version, transforms) into the build outputs.
//
// It performs NO network I/O — that is sandbox-forbidden for build-tool plugins
// and is intentionally separated into `KsealRegisterPlugin`. Registration reads
// the manifest this plugin emits.
//
// Inputs the integrator controls:
//   * `kseal-secure-strings.json` in the target's source directory (optional):
//     a JSON object of identifier → plaintext to harden.
//   * Environment: KSEAL_SDK_VERSION, KSEAL_VERSION_NAME, KSEAL_VERSION_CODE,
//     KSEAL_PROTECTION_PROFILE_ID, KSEAL_BUILD_SEED (all optional; sensible
//     defaults otherwise).

@main
struct KsealHardenPlugin: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) async throws -> [Command] {
        guard let sourceTarget = target as? SourceModuleTarget else { return [] }
        let tool = try context.tool(named: "kseal-harden")
        let work = context.pluginWorkDirectory
        return commands(
            toolPath: tool.path,
            targetName: target.name,
            sourceDir: sourceTarget.directory,
            workDir: work
        )
    }

    private func commands(toolPath: Path, targetName: String, sourceDir: Path, workDir: Path) -> [Command] {
        let env = ProcessInfo.processInfo.environment
        let generated = workDir.appending("KsealSecureStrings.generated.swift")
        let manifest = workDir.appending("kseal-build-proof.json")
        let secureStrings = sourceDir.appending("kseal-secure-strings.json")

        var arguments: [String] = [
            "generate",
            "--target", targetName,
            "--out-strings", generated.string,
            "--out-manifest", manifest.string,
            "--sdk-version", env["KSEAL_SDK_VERSION"] ?? "0.1.0",
            "--version-name", env["KSEAL_VERSION_NAME"] ?? "0.0.0",
            "--version-code", env["KSEAL_VERSION_CODE"] ?? "0",
            "--platform", "ios",
            "--host", "swiftpm-build-plugin",
        ]
        if let profile = env["KSEAL_PROTECTION_PROFILE_ID"], !profile.isEmpty {
            arguments += ["--protection-profile-id", profile]
        }

        var inputFiles: [Path] = []
        if FileManager.default.fileExists(atPath: secureStrings.string) {
            arguments += ["--secure-strings", secureStrings.string]
            inputFiles.append(secureStrings)
        }

        return [
            .buildCommand(
                displayName: "kseal: harden strings + emit build proof for \(targetName)",
                executable: toolPath,
                arguments: arguments,
                inputFiles: inputFiles,
                outputFiles: [generated, manifest]
            )
        ]
    }
}

#if canImport(XcodeProjectPlugin)
import XcodeProjectPlugin

extension KsealHardenPlugin: XcodeBuildToolPlugin {
    func createBuildCommands(context: XcodePluginContext, target: XcodeTarget) throws -> [Command] {
        let tool = try context.tool(named: "kseal-harden")
        let sourceDir = context.xcodeProject.directory.appending(target.displayName)
        return commands(
            toolPath: tool.path,
            targetName: target.displayName,
            sourceDir: sourceDir,
            workDir: context.pluginWorkDirectory
        )
    }
}
#endif
