# tests

Real end-to-end integration suite. This is a self-contained Go module
(`github.com/kennguy3n/kseal/tests`) that imports the server packages directly
via a `replace` directive and drives the **actual** services against a real
Postgres 16 + Redis 7. The only mocked dependencies are the external attestation
platforms (Google Play Integrity / Apple App Attest); even there, only their
trust-material source is swapped, so the real JWS parsing and verdict mapping run.

## Running

```bash
make test-integration            # from the repo root
# or, directly:
cd tests && go test ./...
```

Backing services are provisioned via [testcontainers](https://golang.testcontainers.org/)
when a container runtime is available, or from explicit endpoints when set:

```bash
export KSEAL_TEST_POSTGRES_DSN="postgres://kseal:kseal@localhost:5432/kseal?sslmode=disable"
export KSEAL_TEST_REDIS_ADDR="localhost:6379"
cd tests && go test ./...
```

When neither a DSN nor a container runtime is available, the suite **skips
cleanly** so `go test ./...` stays hermetic. Tests are deterministic and
independently runnable; containers are torn down after the package run.

## Coverage

| File | Expected coverage | What it asserts |
|---|---|---|
| `e2e_trust_flow_test.go` | Trust session E2E + attestation verification | Challenge → platform attestation (mock JWKS, real JWS verify) → trust token → signed request proof → ALLOW/STEP_UP/DENY; anti-replay (decreasing sequence, consumed nonce, wrong token/key) |
| `e2e_telemetry_test.go` | Telemetry ingest/query | zstd batch ingest → read back via `ListEvents` with filters + keyset pagination; quota enforcement; unknown-app rejection |
| `e2e_config_test.go` | Signed config | Ed25519 signature over the full envelope; ETag/`If-None-Match` caching; TTL; version rotation |
| `e2e_webhook_test.go` | Webhook fan-out | HMAC-SHA256 signed delivery; retry/backoff on a failing endpoint |
| `e2e_query_overview_test.go` | Tenant isolation | Per-tenant overview + trust-session stats; cross-tenant reads denied |
| `privacy_contract_test.go` | Privacy contract | Telemetry/event schema carries only minimized, non-PII fields |

> **SDK performance** budgets (startup/memory/binary size) are asserted via the
> Rust Criterion benches under `sdk/rust-core/kseal-core/benches/`, not this Go
> suite. **Policy simulation** outcomes (observe/step-up/block) are exercised by
> the risk-level branches in `e2e_trust_flow_test.go` and the unit tests under
> `server/data-plane/simulator`.
