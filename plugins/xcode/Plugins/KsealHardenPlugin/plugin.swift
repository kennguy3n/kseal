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
        // When a seed is explicitly pinned, forward it as an argument so it is
        // part of this build command's cache key. Otherwise SwiftPM, which keys
        // re-runs on inputs/outputs/arguments, could serve a previously hardened
        // output after the pinned seed changed (the env var alone is invisible to
        // the build graph). The default random-seed path passes no seed, so
        // incremental builds correctly reuse the prior output.
        if let seed = env["KSEAL_BUILD_SEED"], !seed.isEmpty {
            arguments += ["--build-seed", seed]
        }

        var inputFiles: [Path] = []
        if FileManager.default.fileExists(atPath: secureStrings.string) {
            arguments += ["--secure-strings", secureStrings.string]
            inputFiles.append(secureStrings)
        }

        // Only the generated Swift is a declared output (it must be compiled into
        // the target). The manifest is written alongside it in the plugin work
        // directory but is intentionally NOT declared, so SwiftPM does not bundle
        // it as an app resource; KsealRegisterPlugin / CI read it from there.
        return [
            .buildCommand(
                displayName: "kseal: harden strings + emit build proof for \(targetName)",
                executable: toolPath,
                arguments: arguments,
                inputFiles: inputFiles,
                outputFiles: [generated]
            )
        ]
    }
}

#if canImport(XcodeProjectPlugin)
import XcodeProjectPlugin

extension KsealHardenPlugin: XcodeBuildToolPlugin {
    func createBuildCommands(context: XcodePluginContext, target: XcodeTarget) throws -> [Command] {
        let tool = try context.tool(named: "kseal-harden")
        // Locate the secure-strings file among the target's actual inputs rather
        // than guessing a directory layout; fall back to the project directory.
        let configured = target.inputFiles.first { $0.path.lastComponent == "kseal-secure-strings.json" }
        let sourceDir = configured?.path.removingLastComponent() ?? context.xcodeProject.directory
        return commands(
            toolPath: tool.path,
            targetName: target.displayName,
            sourceDir: sourceDir,
            workDir: context.pluginWorkDirectory
        )
    }
}
#endif
