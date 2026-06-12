#!/usr/bin/env bash
#
# Builds libkseal_jni.so for the *host* JDK so JVM unit tests can drive the real
# Rust trust core through the real JNI bridge (no device, no faked core).
#
#   build-host-jni.sh <output-dir>
#
# Steps:
#   1. cargo build -p kseal-ffi      -> libkseal_ffi.a (+ generated kseal.h)
#   2. cc kseal_jni.c + libkseal_ffi.a -> <output-dir>/libkseal_jni.so
#
# The Rust staticlib is linked whole so all kseal_* exports are present in the
# resulting shared object, making it self-contained for the test JVM.
set -euo pipefail

OUT_DIR="${1:?usage: build-host-jni.sh <output-dir>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$ANDROID_DIR/../.." && pwd)"
RUST_CORE="$REPO_ROOT/sdk/rust-core"
JNI_SRC="$ANDROID_DIR/src/main/jni/kseal_jni.c"

# --- Locate a host C compiler ---
CC_BIN="${CC:-cc}"
if ! command -v "$CC_BIN" >/dev/null 2>&1; then
    if command -v gcc >/dev/null 2>&1; then CC_BIN=gcc;
    elif command -v clang >/dev/null 2>&1; then CC_BIN=clang;
    else
        echo "ERROR: no host C compiler (cc/gcc/clang) found; cannot build host JNI." >&2
        exit 1
    fi
fi

# --- Locate JNI headers ---
if [[ -z "${JAVA_HOME:-}" ]]; then
    if command -v javac >/dev/null 2>&1; then
        JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
    fi
fi
if [[ -z "${JAVA_HOME:-}" || ! -f "$JAVA_HOME/include/jni.h" ]]; then
    echo "ERROR: JAVA_HOME/include/jni.h not found (JAVA_HOME='${JAVA_HOME:-}')." >&2
    exit 1
fi

OS="$(uname -s)"
case "$OS" in
    Linux)  JNI_OS_INC="$JAVA_HOME/include/linux"; SOEXT="so"; PLATFORM_LIBS="-lpthread -ldl -lm -lrt" ;;
    Darwin) JNI_OS_INC="$JAVA_HOME/include/darwin"; SOEXT="dylib"; PLATFORM_LIBS="-lpthread -ldl -lm" ;;
    *)      JNI_OS_INC="$JAVA_HOME/include/linux"; SOEXT="so"; PLATFORM_LIBS="-lpthread -ldl -lm" ;;
esac

echo "[build-host-jni] cargo build -p kseal-ffi"
cargo build --manifest-path "$RUST_CORE/Cargo.toml" -p kseal-ffi

HEADER_DIR="$RUST_CORE/kseal-ffi/include"
LIB_A="$RUST_CORE/target/debug/libkseal_ffi.a"
if [[ ! -f "$HEADER_DIR/kseal.h" ]]; then
    echo "ERROR: generated header not found at $HEADER_DIR/kseal.h" >&2
    exit 1
fi
if [[ ! -f "$LIB_A" ]]; then
    echo "ERROR: static lib not found at $LIB_A" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
OUT_SO="$OUT_DIR/libkseal_jni.$SOEXT"

echo "[build-host-jni] linking $OUT_SO"
if [[ "$OS" == "Darwin" ]]; then
    "$CC_BIN" -shared -fPIC \
        -I"$JAVA_HOME/include" -I"$JNI_OS_INC" -I"$HEADER_DIR" \
        "$JNI_SRC" \
        -Wl,-force_load,"$LIB_A" \
        $PLATFORM_LIBS \
        -o "$OUT_SO"
else
    "$CC_BIN" -shared -fPIC \
        -I"$JAVA_HOME/include" -I"$JNI_OS_INC" -I"$HEADER_DIR" \
        "$JNI_SRC" \
        -Wl,--whole-archive "$LIB_A" -Wl,--no-whole-archive \
        $PLATFORM_LIBS \
        -o "$OUT_SO"
fi

# JVM's System.loadLibrary("kseal_jni") expects libkseal_jni.so even on macOS test hosts.
if [[ "$SOEXT" != "so" ]]; then
    cp -f "$OUT_SO" "$OUT_DIR/libkseal_jni.so"
fi

echo "[build-host-jni] done: $OUT_SO"
