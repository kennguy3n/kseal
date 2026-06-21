# kseal-cli

`kseal-cli` is a scriptable command-line client for the kseal control- and
data-plane Connect APIs. It makes the tenant → app → build → policy lifecycle
self-service and reproducible (NoOps): every mutating command supports
`--dry-run`, results render as `--output table|json|yaml`, exit codes are stable
for CI, and the API key is read from the environment or a secret file (it is
never stored in config or printed to output/logs).

New to kseal? Run `kseal init` for a guided setup, then `kseal doctor` to check
your auth, app registration, protection policy, and build proof and get told
exactly what to do next.

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
require a valid key with the necessary scopes; the server rejects an invalid or
missing key with `Unauthenticated` and a valid key without required scopes with
`PermissionDenied`, both of which the CLI surfaces as exit code `3`.

### API key scopes

Tenant API keys must carry the scopes needed by the RPC they call. Empty scope
lists no longer imply full access. Supported scopes follow a hierarchical
namespace model:

| Scope namespace | Grants access to |
|-----------------|------------------|
| `platform:tenant:read` | List tenants |
| `platform:tenant:write` | Create tenants |
| `registry:*` | All registry operations (apps, builds, policies) |
| `registry:read` | Read registry data (apps, builds, policies) |
| `registry:write` | Write registry data (create apps, builds, policies) |
| `policy:*` | All policy operations |
| `policy:read` | Read policies |
| `policy:write` | Write/activate policies |
| `query:*` | All query/telemetry operations |
| `query:read` | Query events and overviews |
| `webhook:*` | All webhook operations |
| `webhook:read` | List webhooks |
| `webhook:write` | Register/delete webhooks |
| `siem:*` | All SIEM connector operations |
| `siem:read` | List SIEM connectors |
| `siem:write` | Register/delete SIEM connectors |
| `compliance:*` | All compliance operations |
| `compliance:read` | Read audit trails, compliance data |
| `compliance:write` | Issue kill switches, manage canary rollouts |
| `*` | All non-platform tenant scopes |

**Platform administration**: Tenant provisioning and tenant enumeration are
platform-admin operations. `CreateTenant` requires `platform:tenant:write`;
`ListTenants` requires `platform:tenant:read`. The principal must also be marked
as a platform admin, so a tenant API key cannot satisfy platform scopes
accidentally.

**Device-plane compatibility**: Public pre-attestation calls remain limited to
nonce issuance and attestation verification, and both require a known app record.
Config and telemetry calls must run under a validated tenant/device credential
context; a request body `tenant_id` is treated as a claim, not authority.

See `docs/authz-hardening.md` for the full authorization hardening model.

Connection settings are supplied by flags, environment variables, or a named
profile. Precedence is always **flag > environment variable > profile**:

| Setting   | Flag         | Env var          | Profile fallback                |
|-----------|--------------|------------------|---------------------------------|
| Profile   | `--profile`  | `KSEAL_PROFILE`  | current profile                 |
| Endpoint  | `--endpoint` | `KSEAL_ENDPOINT` | profile `endpoint` (default `http://localhost:8080`) |
| Tenant    | `--tenant`   | `KSEAL_TENANT`   | profile `tenant`                |
| Output    | `-o/--output`| `KSEAL_OUTPUT`   | `table`                         |
| API key   | (never a flag) | `KSEAL_API_KEY` | profile `api_key_file`         |

### Global flags

| Flag | Description |
|------|-------------|
| `--config` | config file path (default `$KSEAL_CONFIG` or `~/.config/kseal/config.json`) |
| `--profile` | connection profile to use (flag > `$KSEAL_PROFILE` > current profile) |
| `--endpoint` | server base URL (flag > `$KSEAL_ENDPOINT` > profile endpoint) |
| `--tenant` | tenant id scope (flag > `$KSEAL_TENANT` > profile tenant) |
| `-o, --output` | output format: `table` (default), `json`, or `yaml` |
| `--dry-run` | print the request that would be sent without performing any mutation |
| `--debug` | print verbose diagnostics (full error chain, exit code) to stderr |
| `--timeout` | per-request timeout (`0` = no timeout; default `30s`) |

Machine-readable output (`json`/`yaml`) is stable and safe to parse in scripts;
the `yaml` projection carries the same fields as `json`. On failure the CLI
prints a single `error:` line (plus an actionable `hint:` where one applies) and
never a raw stack trace; add `--debug` to see the full cause chain and exit
code.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | success |
| `1` | generic error |
| `2` | usage error (bad flags/args, missing tenant scope, invalid policy file) |
| `3` | authentication failure (invalid/missing API key) or permission denied (missing required scopes) |
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

## Getting started (guided)

`kseal init` writes a connection profile and prints an ordered "get secure fast"
path. It is fully scriptable (`--non-interactive`) and never reads or writes the
API key value — it only records the *name of the env var* to read it from.

```bash
# Interactive: prompts for endpoint/tenant, then prints the next steps.
kseal init

# Non-interactive (CI/bootstrap): write a profile and exit 0.
kseal init --name prod --endpoint https://api.kseal.example.com \
  --tenant-id ten_abc123 --api-key-env KSEAL_API_KEY --non-interactive
```

`kseal doctor` checks the whole onboarding path in dependency order —
configuration → credentials → connectivity → tenant scope → app registration →
protection policy → build proof — and prints, for each gap, *why it matters* and
the exact command to fix it.

```bash
kseal doctor              # human-readable report + verdict
kseal doctor -o json      # machine-readable checks for CI
kseal doctor --strict     # treat setup gaps (warnings) as failures (exit 3)
```

Setup gaps are reported as warnings and exit `0`; only a broken connection or
rejected key is fatal. `--strict` promotes warnings to failures so a pipeline
can block until the app is fully secured.

## Commands

### init / doctor

See [Getting started (guided)](#getting-started-guided) above. `init` and
`doctor` are the recommended entry points for a new app.

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

**Required scopes**: `tenant create` requires `platform:tenant:write`; `tenant
list` requires `platform:tenant:read`; `tenant get` and `tenant update` require
`registry:read` and `registry:write` respectively. Platform administration
commands additionally require the principal to be marked as a platform admin.

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

**Required scopes**: `app create` requires `registry:write`; `app get` and
`app list` require `registry:read`.

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

**Required scopes**: `build register` requires `registry:write`; `build get` and
`build list` require `registry:read`.

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

**Required scopes**: `policy author` and `policy activate` require `policy:write`;
`policy list` and `policy get-active` require `policy:read`; `policy simulate`
requires `query:read`.

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

**Required scopes**: `profile create` requires `policy:write`; `profile list`
requires `policy:read`.

### webhook

Manage tenant webhooks for event fan-out.

```bash
kseal webhook register --url https://hooks.acme.example.com/kseal \
  --event-type ROOT_RISK --event-type DEBUGGER   # empty = all event types
kseal webhook list
kseal webhook delete <webhook-id>
```

**Required scopes**: `webhook register` and `webhook delete` require `webhook:write`;
`webhook list` requires `webhook:read`.

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

**Required scopes**: `events query` and `events tail` require `query:read`.

### compliance

Generate store-disclosure artifacts and read compliance/audit state.

```bash
# Local generators (offline, no server required)
kseal compliance privacy-manifest --format plist --out PrivacyInfo.xcprivacy
kseal compliance data-safety --format md --out datasafety.md
kseal compliance mastg --catalog ./mastg-catalog.md --evidence ./evidence.json

# Server-backed reads (require authentication + tenant scope)
kseal compliance audit-trail --action policy.activate
kseal compliance kill-switch --app <app-id>
kseal compliance data-processing-registry
```

**Required scopes**: Local generators (`privacy-manifest`, `data-safety`, `mastg`)
require no server access. Server-backed commands require `compliance:read` for
audit-trail, kill-switch, and data-processing-registry reads.

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

## Troubleshooting

### Permission denied (exit code 3)

If you receive a permission denied error with exit code 3, your API key is valid
but lacks the required scope for the command you're trying to run.

```bash
$ kseal tenant list
error: PermissionDenied: missing required scope platform:tenant:read
hint: Ensure your API key includes the platform:tenant:read scope
# Exit code: 3
```

**To fix this**:
1. Check the required scopes for your command in the command reference above
2. Create or update your API key to include the required scopes
3. If using a platform admin command (e.g., `tenant create`), ensure your
   principal is marked as a platform admin in addition to having the required
   scopes

### Authentication failure (exit code 3)

If you receive an authentication failure error with exit code 3, your API key is
invalid or missing.

```bash
$ kseal app list
error: Unauthenticated: invalid API key
hint: Check that KSEAL_API_KEY is set and valid
# Exit code: 3
```

**To fix this**:
1. Verify that `KSEAL_API_KEY` (or your profile's `api_key_env`) is set correctly
2. Check that the API key hasn't been revoked or expired
3. Ensure you're using the correct endpoint for your environment

## Discoverability

Shell completions are generated for bash, zsh, fish, and PowerShell:

```bash
# bash (current shell)
source <(kseal completion bash)
# zsh (persist)
kseal completion zsh > "${fpath[1]}/_kseal"
# fish
kseal completion fish > ~/.config/fish/completions/kseal.fish
```

Generate troff man pages for the whole command tree (no server needed):

```bash
kseal man --dir ./man    # writes kseal.1, kseal-init.1, kseal-doctor.1, …
man ./man/kseal-doctor.1
```

Every command documents flags and copy/paste examples in `kseal <command>
--help`.

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
