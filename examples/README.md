# kseal examples

Minimal, runnable quickstarts that integrate the kseal SDKs / API on `main`. Each
demonstrates the same device-plane trust flow end-to-end:

```
GetNonce → VerifyAttestation → ValidateRequestProof  (ALLOW / STEP_UP / DENY)
```

| Example | Surface | Build/run | What's mocked |
|---|---|---|---|
| [`backend-quickstart`](backend-quickstart) | Go: registry + trust + query services, plus a `curl` script | `go run .` / `go test ./...` / `./curl-quickstart.sh` | Google Play Integrity JWKS (swapped for a local key, the documented test path) |
| [`android`](android) | Android SDK (Kotlin) | `./gradlew :app:installDebug` | External Play Integrity provider |
| [`ios`](ios) | iOS SDK (Swift) | `swift run kseal-ios-quickstart` | External App Attest / DeviceCheck provider |
| [`desktop-macos`](desktop-macos) | macOS desktop SDK (Swift) | `swift run kseal-desktop-quickstart` | External code-signing notary |

## Common principle

Across all four, **only the external third-party attestation provider is mocked**
(Play Integrity, App Attest, the notary). Everything internal is real: the native
RASP probes, the shared Rust trust core's risk scoring and request-proof HMAC,
nonce binding/anti-replay, trust-token minting, and the `TrustService` /
`QueryService` RPCs. The SDK never makes the trust decision — the **server
decides** — so the samples are honest about fail-closed rejections when a real
platform attestation isn't available.

The **backend quickstart is the one that runs the full attestation→token→proof
chain locally** (it swaps the server's JWKS source for a local key, exactly like
`tests/e2e_trust_flow_test.go`). The mobile/desktop samples drive the real
device-side SDK and transport; their `VerifyAttestation` step needs a real
platform attestation (or a server configured to accept a dev one).

## Server

All samples talk to the server from the repo's local stack. From the repo root:

```bash
make docker-up        # server :8080 + Postgres :5432 + Redis :6379 + dashboard
```

Provision a tenant/app once with the backend seeder and reuse the ids everywhere:

```bash
cd examples/backend-quickstart && eval "$(go run . -seed)"
# exports KSEAL_TENANT, KSEAL_APP, KSEAL_API_KEY
```
