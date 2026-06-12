#!/usr/bin/env bash
# Regenerate the Connect-Web TypeScript client into web/console/src/gen.
#
# The canonical protobuf schemas live in //proto (their own buf module) and are
# owned by another component; this console must not modify them. We generate the
# TypeScript client straight from that module so the console always tracks the
# same source of truth as the rest of the repo — including the read-side
# QueryService (kseal/v1/query.proto + kseal/v1/query_service.proto).
#
# Requires: buf on PATH and `npm install` already run (for protoc-gen-es).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${CONSOLE_DIR}/../.." && pwd)"
CANONICAL_PROTO="${REPO_ROOT}/proto"

if [ ! -f "${CANONICAL_PROTO}/buf.yaml" ]; then
  echo "error: canonical proto module not found at ${CANONICAL_PROTO}" >&2
  exit 1
fi

cd "${CONSOLE_DIR}"
buf generate "${CANONICAL_PROTO}" --template buf.gen.yaml

echo "==> generated TypeScript client in src/gen"
