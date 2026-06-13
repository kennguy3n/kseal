// swift-tools-version:5.9
import PackageDescription

// KsealHarden — the iOS build-time hardening toolkit.
//
// Ships three things that integrators consume:
//   * `KsealHardenCore`     — portable, dependency-free hardening logic
//                             (polymorphism seed, string obfuscation,
//                             symbol/metadata stripping, build-proof manifest,
//                             RegistryService client). Fully unit-testable on
//                             any platform with a Swift toolchain.
//   * `kseal-harden`        — the build-tool executable the plugins invoke.
//   * `KsealHardenPlugin`   — a SwiftPM/Xcode **build-tool plugin** that runs
//                             string hardening + build-proof emission at build
//                             time (no network — sandbox safe).
//   * `KsealRegisterPlugin` — a command plugin that registers the emitted
//                             build proof with `RegistryService.CreateBuild`
//                             (network-permitted), with an offline fallback.
//
// App Store safety: every transform uses only the public Swift/Clang toolchain
// (codegen, `strip`, `otool`, standard linker dead-strip flags). No private
// APIs, no entitlement abuse, no dynamic code download. See
// ../../docs/build-hardening-ios.md and ../../docs/ios-app-review.md.
let package = Package(
    name: "KsealHarden",
    platforms: [
        .macOS(.v12),
    ],
    products: [
        .library(name: "KsealHardenCore", targets: ["KsealHardenCore"]),
        .executable(name: "kseal-harden", targets: ["kseal-harden"]),
        .plugin(name: "KsealHardenPlugin", targets: ["KsealHardenPlugin"]),
        .plugin(name: "KsealRegisterPlugin", targets: ["KsealRegisterPlugin"]),
        .plugin(name: "KsealMasvsReportPlugin", targets: ["KsealMasvsReportPlugin"]),
    ],
    targets: [
        .target(
            name: "KsealHardenCore"
        ),
        .executableTarget(
            name: "kseal-harden",
            dependencies: ["KsealHardenCore"]
        ),
        .plugin(
            name: "KsealHardenPlugin",
            capability: .buildTool(),
            dependencies: ["kseal-harden"]
        ),
        .plugin(
            name: "KsealRegisterPlugin",
            capability: .command(
                intent: .custom(
                    verb: "kseal-register",
                    description: "Register the emitted kseal build proof with RegistryService.CreateBuild."
                ),
                permissions: [
                    .allowNetworkConnections(
                        scope: .all(),
                        reason: "Register the build proof with the kseal control plane (RegistryService.CreateBuild)."
                    )
                ]
            ),
            dependencies: ["kseal-harden"]
        ),
        .plugin(
            name: "KsealMasvsReportPlugin",
            capability: .command(
                intent: .custom(
                    verb: "kseal-masvs-report",
                    description: "Generate a MASVS evidence report from the emitted build proof."
                ),
                permissions: [
                    .writeToPackageDirectory(
                        reason: "Write the generated MASVS evidence report (Markdown + JSON) next to the build proof."
                    )
                ]
            )
        ),
        .testTarget(
            name: "KsealHardenCoreTests",
            dependencies: ["KsealHardenCore"]
        ),
        // End-to-end test that builds the Fixtures/HardenedApp package with the
        // build-tool plugin applied and asserts the emitted artifacts. Skips
        // cleanly when no Swift toolchain is reachable for the nested build.
        .testTarget(
            name: "KsealHardenIntegrationTests",
            dependencies: ["KsealHardenCore"]
        ),
    ]
)
