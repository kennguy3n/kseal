#!/usr/bin/env bash
# curl-quickstart.sh — drive the kseal HTTP/JSON (Connect) API against a live
# server with nothing but curl. It shows the device-plane entry point (GetNonce),
# an authenticated QueryService read (trust-token validation evidence lives in
# the trust-session stats), and the request bodies for the attestation/proof RPCs.
#
# Prerequisites:
#   1. A running server + Postgres + Redis:  make docker-up   (or `make up`)
#   2. A control-plane API key + tenant/app. Provision them once with the seeder,
#      which writes to the same database the server uses:
#
#        eval "$(go run . -seed)"
#
#      That exports KSEAL_API_KEY, KSEAL_TENANT, and KSEAL_APP into your shell.
#
# Then:  ./curl-quickstart.sh
#
# Note on attestation: VerifyAttestation requires a real Google Play Integrity
# (or Apple App Attest) token, which cannot be minted with curl. Step 4 prints
# the exact request body shape; for a fully runnable attestation->token->proof
# chain with the external provider mocked, run the in-process demo: `go run .`.
set -euo pipefail

ENDPOINT="${KSEAL_ENDPOINT:-http://localhost:8080}"
: "${KSEAL_API_KEY:?set KSEAL_API_KEY (run: eval \"\$(go run . -seed)\")}"
: "${KSEAL_TENANT:?set KSEAL_TENANT (run: eval \"\$(go run . -seed)\")}"
: "${KSEAL_APP:?set KSEAL_APP (run: eval \"\$(go run . -seed)\")}"

rpc() { # rpc <Service/Method> <json-body> [extra curl args...]
  local method="$1" body="$2"; shift 2
  curl -fsS -X POST "${ENDPOINT}/kseal.v1.${method}" \
    -H 'Content-Type: application/json' "$@" -d "${body}"
  echo
}

echo "== 1. Health =="
curl -fsS "${ENDPOINT}/healthz"; echo
curl -fsS "${ENDPOINT}/readyz"; echo

echo "== 2. GetNonce (device-plane challenge; no auth) =="
rpc TrustService/GetNonce \
  "{\"tenant_id\":\"${KSEAL_TENANT}\",\"app_id\":\"${KSEAL_APP}\",\"platform\":\"PLATFORM_ANDROID\"}"

echo "== 3. QueryService reads (authenticated with the API key) =="
echo "-- GetTenantOverview --"
rpc QueryService/GetTenantOverview \
  "{\"tenant_id\":\"${KSEAL_TENANT}\"}" \
  -H "Authorization: Bearer ${KSEAL_API_KEY}"
echo "-- GetTrustSessionStats (trust-token validation evidence) --"
rpc QueryService/GetTrustSessionStats \
  "{\"tenant_id\":\"${KSEAL_TENANT}\"}" \
  -H "Authorization: Bearer ${KSEAL_API_KEY}"

cat <<'EOF'
== 4. VerifyAttestation + ValidateRequestProof (body shapes) ==
These complete the trust flow but need a real platform attestation token, so
they are shown here as request shapes only. Run `go run .` for a runnable chain
with Play Integrity mocked via the documented test path.

Connect's JSON codec accepts EITHER snake_case (proto field names, shown below)
or camelCase on input, and ALWAYS emits camelCase in responses (and int64 as a
quoted string), e.g. GetNonce above returns {"nonce":"...","expiresAt":"..."}.

POST /kseal.v1.TrustService/VerifyAttestation
{
  "tenant_id": "<tenant>",
  "app_id": "<app>",
  "platform": "PLATFORM_ANDROID",
  "nonce": "<base64 nonce from GetNonce>",
  "build_hash": "sha256:...",
  "instance_id": "<stable non-PII install id>",
  "platform_attestation_token": "<base64 Play Integrity JWS>"
}
# -> { "accepted": true, "trustToken": { "tokenId": "...", "riskLevel": "TRUST_LEVEL_TRUSTED", ... }, "signedToken": "<base64 Ed25519 JWT>" }

POST /kseal.v1.TrustService/ValidateRequestProof
{
  "trust_token_id": "<token_id>",
  "request_hash": "<base64 sha256 of the canonical request>",
  "nonce": "<base64 per-request nonce>",
  "app_instance_signature": "<base64 HMAC over the canonical proof preimage>",
  "monotonic_sequence": 1
}
# -> { "decision": "DECISION_ALLOW" }  (STEP_UP / DENY for riskier sessions or replays)
EOF
