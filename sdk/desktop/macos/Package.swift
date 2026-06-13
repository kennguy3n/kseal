// swift-tools-version:5.9
import PackageDescription
import Foundation

// The macOS desktop SDK links the **already-built** kseal trust core through the
// generated C ABI (`kseal.h`) exactly like the mobile SDKs — it does NOT rebuild
// or modify the Rust crate. Unlike the iOS package (which links the static
// archive), the desktop package links the **shared** library (`libkseal_ffi.so`
// on a Linux test host, `libkseal_ffi.dylib` on macOS). Dynamic linking keeps
// the SDK footprint small, matches the "link the cdylib" integration contract,
// and avoids the host-toolchain autolink mismatch that the static archive trips
// on non-Apple CI.
//
// `scripts/build-rust-host.sh` produces the shared library + stages the header.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let rustDebugDir = "\(packageDir)/../../rust-core/target/debug"

let hostLinkerFlags: [LinkerSetting] = [
    // Link the kseal-ffi shared library by search path and add an rpath so the
    // test runner resolves it at load time (no install step required).
    .unsafeFlags(["-L\(rustDebugDir)", "-lkseal_ffi"], .when(platforms: [.linux, .macOS])),
    .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", rustDebugDir], .when(platforms: [.linux, .macOS])),
]

let package = Package(
    name: "KsealDesktop",
    platforms: [
        .macOS(.v11),
    ],
    products: [
        .library(name: "KsealDesktop", targets: ["KsealDesktop"]),
    ],
    targets: [
        // C-interop target exposing the cbindgen-generated kseal.h.
        .target(
            name: "CKseal",
            sources: ["shim.c"],
            publicHeadersPath: "include"
        ),
        // Public Swift SDK: native macOS integrity probes + trust orchestration
        // over the shared Rust core.
        .target(
            name: "KsealDesktop",
            dependencies: ["CKseal"],
            linkerSettings: hostLinkerFlags
        ),
        .testTarget(
            name: "KsealDesktopTests",
            dependencies: ["KsealDesktop"],
            linkerSettings: hostLinkerFlags
        ),
    ]
)
