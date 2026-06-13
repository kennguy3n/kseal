#!/usr/bin/env bash
#
# Builds the Rust trust core's *shared* library for the host so `dotnet test`
# can P/Invoke the real `kseal-ffi` C ABI (no faked core). Prints the path to
# export as KSEAL_FFI_LIBRARY (consumed by NativeMethods' DllImportResolver).
#
# The Windows SDK consumes the prebuilt cdylib exactly like the mobile SDKs
# consume the FFI — the Rust crate is not modified.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WINDOWS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$WINDOWS_DIR/../../.." && pwd)"
RUST_CORE="$REPO_ROOT/sdk/rust-core"

echo "[build-rust-host] cargo build -p kseal-ffi"
cargo build --manifest-path "$RUST_CORE/Cargo.toml" -p kseal-ffi

case "$(uname -s)" in
    Darwin) LIB="libkseal_ffi.dylib" ;;
    MINGW*|MSYS*|CYGWIN*) LIB="kseal_ffi.dll" ;;
    *)      LIB="libkseal_ffi.so" ;;
esac
echo "[build-rust-host] shared lib -> $RUST_CORE/target/debug/$LIB"
echo "export KSEAL_FFI_LIBRARY=$RUST_CORE/target/debug/$LIB"
