#!/usr/bin/env bash
# Regenerate the Connect-Web TypeScript client for the CONSOLE-LOCAL proto module
# into web/console/src/gen-local.
#
# Unlike scripts/gen-proto.sh (which generates from the canonical //proto module
# the console must not modify), this generates from proto-local/ — the
# compliance/ops RPCs WS-K is adding to the canonical module. The console talks
# to them through this generated client and degrades gracefully until they land
# on the canonical module, at which point the parent re-points it at src/gen.
#
# Requires: buf on PATH and `npm install` already run (for protoc-gen-es).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCAL_PROTO="${CONSOLE_DIR}/proto-local"

if [ ! -f "${LOCAL_PROTO}/buf.yaml" ]; then
  echo "error: console-local proto module not found at ${LOCAL_PROTO}" >&2
  exit 1
fi

cd "${CONSOLE_DIR}"
buf generate "${LOCAL_PROTO}" --template buf.gen.local.yaml

echo "==> generated console-local TypeScript client in src/gen-local"
