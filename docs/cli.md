# kseal-cli

`kseal-cli` is a scriptable command-line client for the kseal control- and
data-plane Connect APIs. It makes the tenant → app → build → policy lifecycle
self-service and reproducible (NoOps): every mutating command supports
`--dry-run`, results render as `--output table|json`, exit codes are stable for
CI, and the API key is read from the environment or a secret file (it is never
stored in config or printed to output/logs).

The CLI lives in its own Go module under `cmd/kseal-cli/` and imports the
generated server Connect clients and shared risk helpers read-only.

## Install / build

```bash
cd cmd/kseal-cli
go build -o kseal .
# or install onto your PATH
go install .
```

## Authentication & connection

The CLI never stores secret values. The API key is resolved at runtime from
(in order):

1. the environment variable named by the active profile's `api_key_env`
   (default `KSEAL_API_KEY`), then
2. the file at the active profile's `api_key_file`, if set.

The key is sent as `Authorization: Bearer <key>`. Control-plane procedures
require a valid key; the server rejects an invalid/absent key with
`Unauthenticated`, which the CLI surfaces as exit code `3`.

Connection settings are supplied by flags or a named profile:

| Setting   | Flag         | Env / profile fallback                        |
|-----------|--------------|-----------------------------------------------|
| Endpoint  | `--endpoint` | profile `endpoint` (default `http://localhost:8080`) |
| Tenant    | `--tenant`   | profile `tenant`                              |
| API key   | (never a flag) | `KSEAL_API_KEY` env or profile `api_key_file` |

### Global flags

| Flag | Description |
|------|-------------|
| `--config` | config file path (default `$KSEAL_CONFIG` or `~/.config/kseal/config.json`) |
| `--profile` | connection profile to use (default: current profile) |
| `--endpoint` | server base URL (overrides the profile endpoint) |
| `--tenant` | tenant id scope (overrides the profile tenant) |
| `-o, --output` | output format: `table` (default) or `json` |
| `--dry-run` | print the request that would be sent without performing any mutation |
| `--timeout` | per-request timeout (`0` = no timeout; default `30s`) |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | generic error |
| `2` | usage error (bad flags/args, missing tenant scope, invalid policy file) |
| `3` | authentication failure (invalid/missing API key) |
| `4` | not found |
| `5` | server unavailable |
| `6` | invalid input rejected by the server |

## Tenant scoping

Every tenant-scoped command requires a tenant id from `--tenant` or the active
profile. If neither is set the command fails with a usage error (`2`) before any
RPC. The server independently enforces that the API key's tenant matches the
requested resource, so a key for tenant A cannot read or mutate tenant B.

## Configuration profiles

Profiles store an endpoint, a default tenant, and *where to read the API key
from* — never the key itself.

```bash
# Create/update a profile and make it current.
kseal config set-profile \
  --name prod \
  --endpoint https://api.kseal.example.com \
  --tenant-id ten_abc123 \
  --api-key-env KSEAL_API_KEY \
  --use

kseal config list            # show all profiles (no secrets)
kseal config current         # show the active profile
kseal config use staging     # switch the current profile
kseal config remove staging  # delete a profile
```

With a profile active, tenant-scoped commands need no `--tenant`:

```bash
export KSEAL_API_KEY=...      # value lives only in your shell/secret store
kseal app list
```

## Commands

### tenant

Manage tenants (the control-plane isolation boundary).

```bash
kseal tenant create --name "Acme" --slug acme --tier growth
kseal tenant get <tenant-id>
kseal tenant list --page-size 50
kseal tenant update <tenant-id> --tier enterprise --status active
```

`--tier` is one of `starter|growth|enterprise|regulated`; `--status` is one of
`active|suspended|deleted`.

### app

Manage apps within a tenant.

```bash
kseal app create \
  --name "Acme Wallet" \
  --platform android \
  --package-id com.acme.wallet \
  --signing-identity sha256:AA.. --signing-identity sha256:BB..
kseal app get <app-id>
kseal app list
```

`--platform` is `android|ios`; `--signing-identity` is repeatable.

### build

Register protected builds. `build register` ingests the manifest emitted by the
Gradle/Xcode build plugins; explicit flags override fields from the file.

```bash
kseal build register --manifest-file ./build/kseal-manifest.json
# override individual fields
kseal build register --manifest-file ./m.json --version-name 1.4.0 --version-code 140
kseal build get <build-id>
kseal build list --app-id <app-id>
```

Manifest file shape:

```json
{
  "app_id": "app_123",
  "build_hash": "sha256:abc123",
  "version_name": "1.2.3",
  "version_code": 42,
  "protection_profile_id": "prof_123",
  "manifest": {"modules": ["rasp", "integrity"], "tool": "gradle-plugin@1.0"}
}
```

`app_id` and `build_hash` are required (from the file or via `--app-id` /
`--build-hash`).

### policy

Author, validate, activate, and simulate enforcement policies.

```bash
# Validate locally (no server call); non-zero exit if there are problems.
kseal policy validate --file ./policy.json

# Create a new (inactive) version, then activate it.
kseal policy author --file ./policy.json --app-id <app-id>
kseal policy activate <policy-id>

kseal policy list --app-id <app-id>
kseal policy get-active --app-id <app-id>
```

Policy authoring file shape:

```json
{
  "name": "baseline",
  "enforcement_mode": "block",
  "rules": {"rules": [], "signal_weights": {"0": 100}},
  "risk_thresholds": {"HIGH_RISK": 90, "CRITICAL": 130},
  "modules_enabled": ["rasp", "attestation"]
}
```

`enforcement_mode` is `observe|step_up|block`. Threshold keys are TrustLevel
names (`LOW_RISK|MEDIUM_RISK|HIGH_RISK|CRITICAL`); `signal_weights` keys are risk
bit indices (`0`–`63`).

#### policy simulate

Replay recent stored traffic to forecast how a candidate policy would change
decisions before you activate it. The simulation reuses the server's
authoritative risk scoring (`Score → Level → Decision`) for production parity,
diffing the candidate against the currently active policy.

```bash
kseal policy simulate \
  --candidate-file ./candidate.json \
  --app-id <app-id> \
  --max-events 5000 \
  -o json
```

Report fields: `total`, `current_counts` / `candidate_counts` (decisions by
`ALLOW|STEP_UP|DENY`), `changed`, `newly_blocked`, and `newly_allowed`.

### profile

Manage protection profiles (reusable module + mode bundles).

```bash
kseal profile create --name "high-security" --default-mode block --module rasp --module attestation
kseal profile list
```

### webhook

Manage tenant webhooks for event fan-out.

```bash
kseal webhook register --url https://hooks.acme.example.com/kseal \
  --event-type ROOT_RISK --event-type DEBUGGER   # empty = all event types
kseal webhook list
kseal webhook delete <webhook-id>
```

### events

Query and tail stored risk events via the QueryService.

```bash
# Keyset-paginated query with filters.
kseal events query --app-id <app-id> --risk-level HIGH_RISK --risk-level CRITICAL \
  --start 1717200000000 --end 1717286400000 --page-size 200 -o json

# Continuously stream new events (Ctrl-C to stop).
kseal events tail --interval 2s --risk-level CRITICAL
```

Filters (`--event-type`, `--risk-level`) are repeatable; time bounds are unix
milliseconds (`0` = unbounded).

## Scripting examples

Fail fast in CI (any non-zero exit aborts the script):

```bash
set -euo pipefail
export KSEAL_API_KEY="$(vault read -field=key secret/kseal/ci)"

APP_ID=$(kseal app create --name "Acme Wallet" --platform android \
  --package-id com.acme.wallet -o json | jq -r .id)

kseal build register --manifest-file ./build/kseal-manifest.json -o json >/dev/null

# Gate a rollout on the simulated blast radius.
NEWLY_BLOCKED=$(kseal policy simulate --candidate-file ./candidate.json \
  --app-id "$APP_ID" -o json | jq .newly_blocked)
if [ "$NEWLY_BLOCKED" -gt 100 ]; then
  echo "candidate would newly block $NEWLY_BLOCKED requests; aborting" >&2
  exit 1
fi

POLICY_ID=$(kseal policy author --file ./candidate.json --app-id "$APP_ID" -o json | jq -r .id)
kseal policy activate "$POLICY_ID"
```

Preview any mutation without performing it:

```bash
kseal policy activate "$POLICY_ID" --dry-run
```

## Testing

Command tests run against an in-process Connect server built from the real
service handlers (`registry`, `webhook`, `query`) backed by the in-memory store
and analytics store, fronted by the real interceptor chain (including API-key
auth). They cover happy paths, auth failure (`401`), `--dry-run` (asserting no
mutation occurred), strict tenant scoping, and golden `--output json` snapshots.

```bash
cd cmd/kseal-cli
go test -race ./...
# regenerate golden files after an intentional output change
go test ./... -update
```
