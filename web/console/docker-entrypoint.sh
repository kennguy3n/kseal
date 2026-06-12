#!/bin/sh
# Renders /env.js at container start so a single prebuilt image can be pointed
# at any kseal API endpoint without rebuilding (NoOps deploy-time config).
#
# KSEAL_API_BASE_URL — full origin of the kseal server (e.g. https://api.example
# .com). When unset/empty the app falls back to the build-time
# VITE_KSEAL_API_BASE_URL baked into the bundle.
set -eu

TARGET="/usr/share/nginx/html/env.js"
API_BASE_URL="${KSEAL_API_BASE_URL:-}"

# env.js is loaded as a <script>, so the value MUST be escaped before being
# embedded in a JS string literal — an unescaped " or \ (or </script>) would
# let an operator-controlled env var inject arbitrary JavaScript (XSS). Escape
# backslash, double-quote, angle brackets, and strip CR/LF.
SAFE_URL=$(printf '%s' "${API_BASE_URL}" \
  | tr -d '\r\n' \
  | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/</\\u003c/g' -e 's/>/\\u003e/g')

cat > "${TARGET}" <<EOF
// Generated at container start from KSEAL_API_BASE_URL. Do not edit.
window.__KSEAL_ENV__ = { apiBaseUrl: "${SAFE_URL}" };
EOF

echo "kseal-console: rendered ${TARGET} (apiBaseUrl='${API_BASE_URL}')"
