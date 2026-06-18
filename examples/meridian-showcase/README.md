# Meridian Pay showcase seeder

This command seeds a running kseal stack with the **canonical Meridian Pay
dataset** used throughout the documentation and the [showcase](../../docs/showcase/).
It exists so anyone can reproduce the console views and worked examples on a
local stack — it is a development/operations helper, not part of the product.

It provisions, for a single tenant (`meridian`):

- two apps — `pay-android` (consumer wallet) and `merchant` — each with several
  builds, a protection profile, and a JSON manifest that drives the MASVS
  evidence view;
- an active step-up policy per app (matching
  [`docs/reference/fixtures/control/policy.json`](../../docs/reference/fixtures/control/policy.json))
  plus a tighter candidate policy for the canary;
- a console API key, two webhooks, a Splunk HEC SIEM connector, a
  data-processing registry, a hash-chained audit trail, an armed kill switch
  (a repackaged build) plus a re-enabled one, and a 25% canary rollout;
- ~125 trust sessions across the five trust levels (plus failed attestations); and
- ~440 telemetry events submitted over the public device-plane ingest API, so
  the server derives a realistic risk-level distribution.

## Usage

Start the full stack first (Postgres, Redis, server, console):

```bash
docker compose up --build      # or: make up
```

Then run the seeder against it:

```bash
cd examples/meridian-showcase
go run . \
  -dsn 'postgres://kseal:kseal@localhost:5432/kseal?sslmode=disable' \
  -kek ZGV2LW9ubHkta3NlYWwta2VrLTMyLWJ5dGVzLWFhYWE= \
  -ingest-url http://localhost:8080
```

The defaults already match the committed `docker-compose.yml`, so plain
`go run .` works against a default local stack. The `-kek` value must be the
same base64 KEK the server reads from `KSEAL_KEK` (it is used to decrypt the
tenant signing key when signing kill switches).

On success it prints the generated API key and the tenant UUID. Sign in to the
console at <http://localhost:5173/login> with:

- **API base URL** — `http://localhost:8080`
- **Tenant ID** — the printed tenant UUID
- **API key** — the printed `ksk_…` key

The seeder expects a clean database. To re-run it, reset the stack
(`make clean && make up`) or `TRUNCATE tenants CASCADE` and start the server
fresh so the in-memory event store is cleared too.
