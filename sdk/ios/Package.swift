// swift-tools-version:5.9
import PackageDescription
import Foundation

// Absolute path to the Rust trust core's host build output. The static archive
// (libkseal_ffi.a) is produced by scripts/build-rust-host.sh and linked by path
// so `swift test` exercises the REAL core on the host. For on-device builds the
// integrator links the per-arch slice from the xcframework instead (see
// scripts/build-xcframework.sh) — these host flags apply only to linux/macOS.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let rustDebugLib = "\(packageDir)/../rust-core/target/debug/libkseal_ffi.a"

let hostLinkerFlags: [LinkerSetting] = [
    .unsafeFlags([rustDebugLib], .when(platforms: [.linux])),
    .unsafeFlags(["-lpthread", "-ldl", "-lm"], .when(platforms: [.linux])),
    .unsafeFlags([rustDebugLib], .when(platforms: [.macOS])),
]

let package = Package(
    name: "KsealSDK",
    platforms: [
        .iOS(.v13),
        .macOS(.v11),
    ],
    products: [
        .library(name: "KsealSDK", targets: ["KsealSDK"]),
    ],
    targets: [
        // C-interop target exposing the cbindgen-generated kseal.h.
        .target(
            name: "CKseal",
            sources: ["shim.c"],
            publicHeadersPath: "include"
        ),
        // Public Swift SDK wrapping the core + native RASP probes.
        .target(
            name: "KsealSDK",
            dependencies: ["CKseal"],
            linkerSettings: hostLinkerFlags
        ),
        .testTarget(
            name: "KsealSDKTests",
            dependencies: ["KsealSDK"],
            linkerSettings: hostLinkerFlags
        ),
    ]
)
