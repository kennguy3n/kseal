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

# Tighten the CSP connect-src to the configured kseal API origin so the browser
# only allows API calls to that origin. We can only derive it from the runtime
# env var; when KSEAL_API_BASE_URL is unset (build-time-configured deploys) or
# is not a clean http(s) origin we leave connect-src '*' rather than guess.
# The CSP lives in the shared security-headers snippet included by every nginx
# location (see nginx.conf), so we rewrite it there.
CSP_SNIPPET="/etc/nginx/snippets/kseal-security-headers.conf"
CONNECT_SRC="*"
if [ -n "${API_BASE_URL}" ]; then
  ORIGIN=$(printf '%s' "${API_BASE_URL}" \
    | tr -d '\r\n' \
    | sed -E 's#^(https?://[^/]+).*#\1#')
  # Only accept a strict scheme://host[:port] origin; reject anything carrying
  # characters that could break out of the nginx directive or the CSP grammar.
  if printf '%s' "${ORIGIN}" | grep -Eq '^https?://[A-Za-z0-9._-]+(:[0-9]+)?$'; then
    CONNECT_SRC="'self' ${ORIGIN}"
  else
    echo "kseal-console: WARNING KSEAL_API_BASE_URL is not a clean http(s) origin; leaving connect-src permissive"
  fi
fi

if [ -f "${CSP_SNIPPET}" ]; then
  # Idempotent: rewrite whatever the current connect-src value is.
  sed -i -E "s#connect-src [^;]*;#connect-src ${CONNECT_SRC};#" "${CSP_SNIPPET}"
  echo "kseal-console: set CSP connect-src to '${CONNECT_SRC}'"
fi
