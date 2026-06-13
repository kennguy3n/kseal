// swift-tools-version:5.9
import PackageDescription

// Fixture package used by KsealHardenPlugin's integration tests. It applies the
// build-tool plugin to a tiny executable and consumes the generated hardened
// string table, exercising the full plugin path end to end.
let package = Package(
    name: "HardenedApp",
    platforms: [
        .macOS(.v12),
    ],
    dependencies: [
        .package(path: "../.."),
    ],
    targets: [
        .executableTarget(
            name: "HardenedApp",
            // Consumed by the plugin (declared as a build input), not a target resource.
            exclude: ["kseal-secure-strings.json"],
            plugins: [
                // Path-dependency identity is the directory basename ("xcode").
                .plugin(name: "KsealHardenPlugin", package: "xcode"),
            ]
        ),
    ]
)
