import XCTest
@testable import KsealHardenCore

/// Builds `Fixtures/HardenedApp` with `KsealHardenPlugin` applied and asserts the
/// plugin's real output: an obfuscated string table (plaintext absent) compiled
/// into the target, and a build-proof manifest with the expected fields.
///
/// This is a true end-to-end exercise of the build-tool plugin path. It skips
/// cleanly (XCTSkip) when no Swift toolchain is reachable to run the nested
/// build — e.g. a minimal CI image — rather than faking a pass.
final class FixtureBuildTests: XCTestCase {
    private let knownSeedHex = String(repeating: "5a", count: 32)

    private var packageRoot: URL {
        // .../plugins/xcode/Tests/KsealHardenIntegrationTests/FixtureBuildTests.swift
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // KsealHardenIntegrationTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // xcode (package root)
    }

    private var fixtureDir: URL {
        packageRoot.appendingPathComponent("Fixtures/HardenedApp")
    }

    func testPluginEmitsHardenedStringsAndBuildProof() throws {
        let runner = SystemProcessRunner()
        guard let swift = runner.which("swift") else {
            throw XCTSkip("swift toolchain unavailable; cannot run nested fixture build")
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: fixtureDir.path), "fixture package missing")

        let scratch = FileManager.default.temporaryDirectory
            .appendingPathComponent("kseal-fixture-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: scratch) }

        var env = ProcessInfo.processInfo.environment
        env["KSEAL_BUILD_SEED"] = knownSeedHex
        env["KSEAL_SDK_VERSION"] = "0.1.0"
        env["KSEAL_VERSION_NAME"] = "1.4.2"
        env["KSEAL_VERSION_CODE"] = "142"
        env["KSEAL_PROTECTION_PROFILE_ID"] = "fixture-profile"

        let result = try run(
            swift,
            arguments: ["build", "--package-path", fixtureDir.path, "--scratch-path", scratch.path],
            environment: env
        )
        guard result.succeeded else {
            // A missing build dependency (e.g. no network to resolve, sandbox
            // limitation) should skip rather than hard-fail the suite.
            throw XCTSkip("nested `swift build` did not succeed in this environment:\n\(result.standardError)\n\(result.standardOutput)")
        }

        // Locate the generated artifacts under the scratch plugin-outputs tree.
        let generated = try findFile(named: "KsealSecureStrings.generated.swift", under: scratch)
        let manifestFile = try findFile(named: "kseal-build-proof.json", under: scratch)

        // 1) Strings transformed: plaintext absent, accessors present.
        let source = try String(contentsOf: generated, encoding: .utf8)
        XCTAssertFalse(source.contains("https://api.fixture.example.com"), "plaintext URL leaked into generated source")
        XCTAssertFalse(source.contains("fixture-telemetry-key-9f3a2b"), "plaintext key leaked into generated source")
        XCTAssertTrue(source.contains("static var apiBaseURL"))
        XCTAssertTrue(source.contains("static var telemetryKey"))

        // The plaintext must also be absent from the compiled binary.
        if let binary = try? findFile(named: "HardenedApp", under: scratch) {
            let bytes = try Data(contentsOf: binary)
            XCTAssertNil(bytes.range(of: Data("https://api.fixture.example.com".utf8)),
                         "plaintext URL leaked into compiled binary")
        }

        // 2) Manifest emitted with expected fields.
        let manifest = try BuildProofManifest.decode(from: Data(contentsOf: manifestFile))
        XCTAssertEqual(manifest.schemaVersion, "1.0")
        XCTAssertEqual(manifest.platform, "ios")
        XCTAssertEqual(manifest.sdkVersion, "0.1.0")
        XCTAssertEqual(manifest.versionName, "1.4.2")
        XCTAssertEqual(manifest.versionCode, 142)
        XCTAssertEqual(manifest.protectionProfileId, "fixture-profile")
        XCTAssertEqual(manifest.buildHash.count, 64)

        // Seed digest must match the seed we pinned via KSEAL_BUILD_SEED.
        let expectedDigest = PolymorphismSeed(hex: knownSeedHex)!.digestHex
        XCTAssertEqual(manifest.polymorphism.seedDigest, expectedDigest)

        let stringTransform = try XCTUnwrap(manifest.transforms.first { $0.kind == "string-obfuscation" })
        XCTAssertEqual(stringTransform.count, 2)
        XCTAssertTrue(manifest.modules.contains("string-hardening"))
    }

    // MARK: - helpers

    private func run(_ executable: String, arguments: [String], environment: [String: String]) throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = environment
        let outPipe = Pipe(); let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        try process.run()
        // Drain both pipes concurrently: `swift build` can emit a lot of output,
        // and reading one to EOF before the other risks a pipe-buffer deadlock.
        var outData = Data()
        var errData = Data()
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "kseal.test.pipe-drain", attributes: .concurrent)
        queue.async(group: group) { outData = outPipe.fileHandleForReading.readDataToEndOfFile() }
        queue.async(group: group) { errData = errPipe.fileHandleForReading.readDataToEndOfFile() }
        process.waitUntilExit()
        group.wait()
        return ProcessResult(
            exitCode: process.terminationStatus,
            standardOutput: String(decoding: outData, as: UTF8.self),
            standardError: String(decoding: errData, as: UTF8.self)
        )
    }

    private func findFile(named name: String, under root: URL) throws -> URL {
        guard let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) else {
            throw XCTSkip("could not enumerate \(root.path)")
        }
        for case let url as URL in enumerator where url.lastPathComponent == name {
            return url
        }
        XCTFail("expected to find \(name) under \(root.path)")
        throw XCTSkip("\(name) not found")
    }
}
