#!/usr/bin/env bash
#
# Builds libkseal_ffi for the Apple device + simulator architectures and packs
# them into KsealFFI.xcframework for on-device integration. Requires macOS with
# Xcode and the Rust apple targets installed:
#
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# This is the documented, real build wiring for shipping the SDK; it is NOT run
# by `swift test` (host tests link the host static archive via Package.swift).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$IOS_DIR/../.." && pwd)"
RUST_CORE="$REPO_ROOT/sdk/rust-core"
OUT_DIR="$IOS_DIR/build"
HEADERS_DIR="$OUT_DIR/headers"

TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)

mkdir -p "$HEADERS_DIR"

for target in "${TARGETS[@]}"; do
    echo "[xcframework] cargo build --release --target $target"
    cargo build --manifest-path "$RUST_CORE/Cargo.toml" -p kseal-ffi --release --target "$target"
done

# Stage the cbindgen header + module map for the framework.
cp -f "$RUST_CORE/kseal-ffi/include/kseal.h" "$HEADERS_DIR/kseal.h"
cp -f "$IOS_DIR/Sources/CKseal/include/module.modulemap" "$HEADERS_DIR/module.modulemap"

# Combine the two simulator slices (arm64 + x86_64) into one fat lib.
SIM_LIB="$OUT_DIR/libkseal_ffi_sim.a"
lipo -create \
    "$RUST_CORE/target/aarch64-apple-ios-sim/release/libkseal_ffi.a" \
    "$RUST_CORE/target/x86_64-apple-ios/release/libkseal_ffi.a" \
    -output "$SIM_LIB"

rm -rf "$OUT_DIR/KsealFFI.xcframework"
xcodebuild -create-xcframework \
    -library "$RUST_CORE/target/aarch64-apple-ios/release/libkseal_ffi.a" -headers "$HEADERS_DIR" \
    -library "$SIM_LIB" -headers "$HEADERS_DIR" \
    -output "$OUT_DIR/KsealFFI.xcframework"

echo "[xcframework] wrote $OUT_DIR/KsealFFI.xcframework"
