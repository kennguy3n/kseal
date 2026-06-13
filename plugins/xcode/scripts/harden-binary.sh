#!/usr/bin/env bash
#
# harden-binary.sh — strip symbols + metadata from a compiled binary using only
# the public toolchain (`strip`, `nm`, and—on Apple—`otool`). App Store-safe:
# `-x` removes local/debug symbols (standard release hygiene), nothing more.
#
# Usage: harden-binary.sh <path-to-binary-or-static-lib>
#
# Prints a "before -> after" symbol count and (on Apple) verifies the result
# with `otool`. Exits non-zero only on a real failure; if `strip` is missing it
# reports and skips so a non-Apple CI lane does not break.
set -euo pipefail

BINARY="${1:-}"
if [[ -z "$BINARY" ]]; then
    echo "usage: harden-binary.sh <binary>" >&2
    exit 2
fi
if [[ ! -e "$BINARY" ]]; then
    echo "harden-binary: not found: $BINARY" >&2
    exit 2
fi

if ! command -v strip >/dev/null 2>&1; then
    echo "harden-binary: 'strip' unavailable; skipping symbol stripping for $BINARY"
    exit 0
fi

count_symbols() {
    if command -v nm >/dev/null 2>&1; then
        nm "$1" 2>/dev/null | grep -cve '^[[:space:]]*$' || true
    else
        echo 0
    fi
}

BEFORE="$(count_symbols "$BINARY")"
# -x: strip non-global symbols. Works for Mach-O and ELF.
strip -x "$BINARY"
AFTER="$(count_symbols "$BINARY")"

echo "harden-binary: $(basename "$BINARY"): ${BEFORE} -> ${AFTER} symbols"

# On Apple, confirm with otool that the binary is well-formed after stripping.
if command -v otool >/dev/null 2>&1; then
    if ! otool -hv "$BINARY" >/dev/null 2>&1; then
        echo "harden-binary: WARNING otool could not parse $BINARY after strip" >&2
    fi
fi
