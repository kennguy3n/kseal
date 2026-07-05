# Backend quickstart — trust flow + QueryService read

A small, **runnable** walkthrough of the kseal device trust flow against the real
server services, plus a `curl` script for driving the HTTP/JSON API of a live
server.

```
GetNonce → VerifyAttestation → ValidateRequestProof (ALLOW / STEP_UP / DENY)
         → QueryService read (tenant overview + trust-session stats)
```

Everything here builds against the public API surface already on `main`
(`RegistryService`, `TrustService`, `QueryService` and the shared
`crypto`/`trust` helpers). The **only** thing mocked is the external attestation
provider — Google Play Integrity — whose JWKS source is swapped for a locally
generated RSA key, exactly like the documented test path in
[`tests/e2e_trust_flow_test.go`](../../tests/e2e_trust_flow_test.go). The real
JWS parsing, nonce binding, verdict→risk mapping, trust-token minting, and
proof validation all run unchanged.

## Prerequisites

- Go (the repo pins `go 1.25`; `GOTOOLCHAIN=auto` will fetch it automatically).
- Postgres 16 + Redis 7. The easiest way is the repo's local stack:

  ```bash
  make docker-up        # from the repo root: server + Postgres + Redis + dashboard
  ```

  Both Postgres (`localhost:5432`) and Redis (`localhost:6379`) are published to
  the host, which is what this example connects to by default. You can override
  with `KSEAL_POSTGRES_DSN` / `KSEAL_REDIS_ADDR`.

## Option A — in-process demo (`go run .`)

Runs the full chain in-process against Postgres + Redis, mocking Play Integrity.
No API key or running server needed — it wires the real services directly.

```bash
cd examples/backend-quickstart
go run .
```

Expected output (ids will differ):

```
[1] Seed a tenant, app, build, active policy, and a control-plane API key
    tenant_id = …
    app_id    = … (com.kseal.quickstart)
    api_key   = ksk_…   (control-plane: send as `Authorization: Bearer <key>`)

[2] Device plane: GetNonce -> VerifyAttestation -> ValidateRequestProof
    clean device -> trust level TRUSTED, token …
    request proof (seq=1) decision: ALLOW
    replayed proof (seq=1) decision: DENY  (anti-replay)

[3] A risky device steps up / is denied by the SAME policy (server-authoritative)
    tampered/unrecognized device -> trust level CRITICAL, decision DENY

[4] QueryService read: tenant overview + trust-session stats
    apps=1 builds=1 active_policies=1
    trust sessions: total=2 tokens_issued=2 attestations_failed=0 by_level=map[CRITICAL:1 TRUSTED:1]
```

## Option B — curl against a live server

`VerifyAttestation` needs a real Play Integrity / App Attest token, so the curl
script focuses on the calls you can drive over HTTP: health, `GetNonce`
(authenticated), and the `QueryService` reads. It prints the request-body shapes
for the attestation and proof RPCs for reference.

```bash
cd examples/backend-quickstart
# 1. provision a tenant/app/build/policy + API key in the server's database:
eval "$(go run . -seed)"     # exports KSEAL_API_KEY, KSEAL_TENANT, KSEAL_APP
# 2. drive the live API:
./curl-quickstart.sh
```

## How request proofs are built

The proof is an HMAC over a canonical, domain-separated, length-prefixed
preimage shared byte-for-byte with the SDK core
(`crypto.RequestProofPreimage`). The per-session key is derived from the signed
trust token (`trust.DeriveProofKey`), so possession of the token — not a
separate shared secret — authenticates each request. The sequence number must
strictly increase, which is what makes a replayed proof `DENY`. See
[`internal/flow/flow.go`](internal/flow/flow.go) (`buildProof`).

## Test

```bash
go test ./...
```

The integration test drives the same flow and asserts the decisions and read
counts. It **skips cleanly** when Postgres/Redis are not reachable, so it is safe
in a hermetic `go test ./...`.
