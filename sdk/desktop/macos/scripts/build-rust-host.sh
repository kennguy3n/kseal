#!/usr/bin/env bash
#
# Builds the Rust trust core's *shared* library for the host and stages the
# generated C header into the CKseal target so `swift test` compiles + links
# against the real core (no device, no faked core).
#
#   1. cargo build -p kseal-ffi          -> libkseal_ffi.{so,dylib} (+ kseal.h)
#   2. copy kseal.h into Sources/CKseal/include/
#
# The shared library is linked by search path from Package.swift (with an
# rpath), so this script only has to produce it and stage the header. Run before
# `swift build` / `swift test`.
#
# The desktop SDK links the **cdylib** (not the static archive the iOS package
# uses): dynamic linking matches the "link the already-built kseal-ffi cdylib"
# integration contract and avoids the host-toolchain autolink mismatch the
# static archive trips on non-Apple CI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$MACOS_DIR/../../.." && pwd)"
RUST_CORE="$REPO_ROOT/sdk/rust-core"

echo "[build-rust-host] cargo build -p kseal-ffi"
cargo build --manifest-path "$RUST_CORE/Cargo.toml" -p kseal-ffi

HEADER_SRC="$RUST_CORE/kseal-ffi/include/kseal.h"
HEADER_DST="$MACOS_DIR/Sources/CKseal/include/kseal.h"
if [[ ! -f "$HEADER_SRC" ]]; then
    echo "ERROR: generated header not found at $HEADER_SRC" >&2
    exit 1
fi
cp -f "$HEADER_SRC" "$HEADER_DST"
echo "[build-rust-host] staged header -> $HEADER_DST"

case "$(uname -s)" in
    Darwin) LIB="libkseal_ffi.dylib" ;;
    *)      LIB="libkseal_ffi.so" ;;
esac
echo "[build-rust-host] shared lib -> $RUST_CORE/target/debug/$LIB"
