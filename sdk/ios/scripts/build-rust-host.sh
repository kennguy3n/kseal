#!/usr/bin/env bash
#
# Builds the Rust trust core for the *host* and stages the generated C header
# into the CKseal target so `swift test` can compile + link against the real
# core (no device, no faked core).
#
#   1. cargo build -p kseal-ffi          -> libkseal_ffi.a (+ kseal.h)
#   2. copy kseal.h into Sources/CKseal/include/
#
# The static archive is linked by absolute path from Package.swift; this script
# only has to produce it and stage the header. Run before `swift test`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$IOS_DIR/../.." && pwd)"
RUST_CORE="$REPO_ROOT/sdk/rust-core"

echo "[build-rust-host] cargo build -p kseal-ffi"
cargo build --manifest-path "$RUST_CORE/Cargo.toml" -p kseal-ffi

HEADER_SRC="$RUST_CORE/kseal-ffi/include/kseal.h"
HEADER_DST="$IOS_DIR/Sources/CKseal/include/kseal.h"
if [[ ! -f "$HEADER_SRC" ]]; then
    echo "ERROR: generated header not found at $HEADER_SRC" >&2
    exit 1
fi
cp -f "$HEADER_SRC" "$HEADER_DST"
echo "[build-rust-host] staged header -> $HEADER_DST"
echo "[build-rust-host] static lib -> $RUST_CORE/target/debug/libkseal_ffi.a"
