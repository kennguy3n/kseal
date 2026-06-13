// swift-tools-version:5.9
import PackageDescription

// Minimal macOS desktop quickstart. It depends on the kseal desktop SDK by path
// so it always tracks the SDK surface on `main`. The SDK links the shared Rust
// trust core, so build it first:
//
//   ./scripts/build-rust-host.sh        # from the repo root (produces libkseal_ffi)
//
// then:  swift run kseal-desktop-quickstart  (from this directory)
let package = Package(
    name: "kseal-desktop-quickstart",
    platforms: [.macOS(.v11)],
    dependencies: [
        .package(path: "../../sdk/desktop/macos"),
    ],
    targets: [
        .executableTarget(
            name: "kseal-desktop-quickstart",
            dependencies: [
                .product(name: "KsealDesktop", package: "macos"),
            ]
        ),
    ]
)
