#!/usr/bin/env bash
#
# Cross-compiles the Rust trust core (kseal-ffi) into libkseal_ffi.so for the
# Android ABIs the SDK ships, placing each under src/main/jniLibs/<abi>/ so AGP
# bundles it into the AAR and CMake links the JNI bridge against it.
#
# Requirements (install once; see sdk/android/README.md):
#   - Android NDK (matching android.ndkVersion in build.gradle.kts)
#   - cargo-ndk:           cargo install cargo-ndk
#   - rustup Android targets:
#       rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#
# This script never fabricates the .so. If the toolchain is missing it prints
# the exact commands to install it and exits non-zero.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$ANDROID_DIR/../.." && pwd)"
RUST_CORE="$REPO_ROOT/sdk/rust-core"
JNILIBS_DIR="$ANDROID_DIR/src/main/jniLibs"

if ! command -v cargo-ndk >/dev/null 2>&1; then
    cat >&2 <<'EOF'
ERROR: cargo-ndk not found. Install the Android Rust toolchain:

    cargo install cargo-ndk
    rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

Then set ANDROID_NDK_HOME to your installed NDK and re-run:
    ./gradlew cargoBuildAndroid
EOF
    exit 1
fi

if [[ -z "${ANDROID_NDK_HOME:-}" && -z "${NDK_HOME:-}" && -z "${ANDROID_NDK_ROOT:-}" ]]; then
    echo "ERROR: set ANDROID_NDK_HOME (or NDK_HOME/ANDROID_NDK_ROOT) to your NDK install." >&2
    exit 1
fi

mkdir -p "$JNILIBS_DIR"

# Phase 5.2: opt-in compile-time string obfuscation for the shipped .so. Off by
# default so standard builds stay debuggable; set KSEAL_OBFUSCATE_STRINGS=1 for
# hardened release artifacts.
FEATURE_ARGS=()
case "${KSEAL_OBFUSCATE_STRINGS:-0}" in
    1 | true | yes | on)
        echo "[build-rust-android] string obfuscation: ON (--features obfuscate-strings)"
        FEATURE_ARGS+=(--features obfuscate-strings)
        ;;
    *)
        echo "[build-rust-android] string obfuscation: off (set KSEAL_OBFUSCATE_STRINGS=1 to enable)"
        ;;
esac

echo "[build-rust-android] cargo-ndk -> $JNILIBS_DIR"
cargo ndk \
    --manifest-path "$RUST_CORE/Cargo.toml" \
    -t arm64-v8a \
    -t armeabi-v7a \
    -t x86_64 \
    -o "$JNILIBS_DIR" \
    build --release -p kseal-ffi ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}

echo "[build-rust-android] done. ABIs:"
ls -1 "$JNILIBS_DIR"
