#!/usr/bin/env bash
# Regenerate the Connect-Web TypeScript client into web/console/src/gen.
#
# The canonical protobuf schemas live in //proto and are owned by another
# component; this console must not modify them. We therefore vendor a private
# copy of the canonical protos together with the console-local
# proto/kseal/v1/query_service.proto into a single buf module so cross-file
# imports (e.g. kseal/v1/common.proto) resolve, then run buf generate.
#
# Requires: buf on PATH and `npm install` already run (for protoc-gen-es).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONSOLE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${CONSOLE_DIR}/../.." && pwd)"
CANONICAL_PROTO="${REPO_ROOT}/proto"
VENDOR_DIR="${CONSOLE_DIR}/.proto-vendor"

if [ ! -d "${CANONICAL_PROTO}/kseal" ]; then
  echo "error: canonical protos not found at ${CANONICAL_PROTO}/kseal" >&2
  exit 1
fi

rm -rf "${VENDOR_DIR}"
mkdir -p "${VENDOR_DIR}"

# Vendor canonical schemas (read-only copy; source of truth stays in //proto).
cp -R "${CANONICAL_PROTO}/kseal" "${VENDOR_DIR}/kseal"
# Add the console-local read API alongside them.
cp -R "${CONSOLE_DIR}/proto/kseal/." "${VENDOR_DIR}/kseal/"

# Minimal module config so buf treats the vendor dir as one module.
cat > "${VENDOR_DIR}/buf.yaml" <<'YAML'
version: v2
modules:
  - path: .
YAML

cd "${CONSOLE_DIR}"
buf generate "${VENDOR_DIR}" --template buf.gen.yaml

echo "==> generated TypeScript client in src/gen"
