#!/usr/bin/env bash
#
# Phase 5.2 — artifact-level proof that compile-time string obfuscation keeps
# sensitive literals out of the shipped native object's .rodata.
#
# Builds the real kseal-ffi cdylib twice (default + --features obfuscate-strings)
# and asserts a literal that is unique to the trust core
# ("config signature verification failed") is:
#   - PRESENT in the default build (debuggable), and
#   - ABSENT in the obfuscated build.
#
# This is a local/review verification (NOT run by CI); the hermetic round-trip
# and plaintext-absence unit tests in kseal-core/src/obfuscate.rs are the CI
# gate. Run from anywhere:  sdk/rust-core/scripts/verify-string-obfuscation.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_CORE="$(cd "$SCRIPT_DIR/.." && pwd)"

# A literal that originates only in the trust core (config.rs), so its presence
# in the artifact is an unambiguous signal — not something the proto-generated
# reflection code or std might emit independently.
NEEDLE="config signature verification failed"

strings_count() { strings -a "$1" | grep -c -F "$NEEDLE" || true; }

lib_name() {
    case "$(uname -s)" in
        Darwin) echo "libkseal_ffi.dylib" ;;
        *) echo "libkseal_ffi.so" ;;
    esac
}

LIB="$(lib_name)"
# Keep the two builds in separate target dirs (mirroring the Makefile's
# build-rust target) so the workspace's default target/release/ artifact is the
# debuggable build, not the obfuscated one, after this script runs.
DEFAULT_TARGET="$RUST_CORE/target/release/$LIB"
OBF_TARGET="$RUST_CORE/target/obfuscated/release/$LIB"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[verify] building default (debuggable) cdylib"
cargo build --manifest-path "$RUST_CORE/Cargo.toml" -p kseal-ffi --release >/dev/null
cp "$DEFAULT_TARGET" "$WORK/default.$LIB"

echo "[verify] building hardened cdylib (--features obfuscate-strings)"
cargo build --manifest-path "$RUST_CORE/Cargo.toml" -p kseal-ffi --release \
    --features obfuscate-strings --target-dir "$RUST_CORE/target/obfuscated" >/dev/null
cp "$OBF_TARGET" "$WORK/obf.$LIB"

default_hits="$(strings_count "$WORK/default.$LIB")"
obf_hits="$(strings_count "$WORK/obf.$LIB")"

echo "[verify] '$NEEDLE'"
echo "[verify]   default build : $default_hits occurrence(s)"
echo "[verify]   hardened build: $obf_hits occurrence(s)"

rc=0
if [[ "$default_hits" -lt 1 ]]; then
    echo "[verify] FAIL: expected the literal in the default build but found none" >&2
    rc=1
fi
if [[ "$obf_hits" -ne 0 ]]; then
    echo "[verify] FAIL: literal still present in the hardened build" >&2
    rc=1
fi

# Re-confirm the exported C ABI names survive obfuscation (invariant: kseal_*
# symbols must stay stable for the JNI/Swift bridges).
ffi_exports="$(strings -a "$WORK/obf.$LIB" | grep -c '^kseal_' || true)"
echo "[verify] kseal_* exported symbols in hardened build: $ffi_exports"
if [[ "$ffi_exports" -lt 1 ]]; then
    echo "[verify] FAIL: expected kseal_* FFI exports to remain present" >&2
    rc=1
fi

if [[ "$rc" -eq 0 ]]; then
    echo "[verify] OK: plaintext removed, FFI exports intact, artifact builds."
fi
exit "$rc"
