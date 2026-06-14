// swift-tools-version:5.9
import PackageDescription

// Minimal iOS-SDK quickstart, runnable on a macOS host (the iOS SDK package also
// supports macOS for host testing). It depends on the SDK by path so it tracks
// the surface on `main`. The SDK links the Rust trust core, so build it first:
//
//   ./scripts/build-rust-host.sh       # from the repo root
//
// then:  swift run kseal-ios-quickstart   (from this directory)
//
// The exact same `KsealSDK` API is used from a real iOS app target; see README.
let package = Package(
    name: "kseal-ios-quickstart",
    platforms: [.macOS(.v11), .iOS(.v13)],
    dependencies: [
        .package(path: "../../sdk/ios"),
    ],
    targets: [
        .executableTarget(
            name: "kseal-ios-quickstart",
            dependencies: [
                .product(name: "KsealSDK", package: "ios"),
            ]
        ),
    ]
)
