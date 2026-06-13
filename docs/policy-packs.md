# Vertical policy packs

Policy packs are **curated default policies**, shipped as client-side data in the
`kseal` CLI. They let an operator stand up a sensible, vertical-appropriate
policy in one command instead of hand-authoring rules, thresholds, and weights.

There is **no policy-pack RPC**. A pack is applied by composing an ordinary
`RegistryService.CreatePolicy` request from the pack's data — exactly what
`kseal policy author` does — so a pack-created policy is indistinguishable from a
hand-authored one and is validated and scored by the server identically.

## The four bundled verticals

| Pack id    | Vertical | Enforcement | Posture |
|------------|----------|-------------|---------|
| `fintech`  | Banking / payments / wallets | `block` | Strict, fail-closed; heavy weight on attestation, network MITM, and account-takeover signals. |
| `gaming`   | Games / real-money gaming    | `step_up` | Anti-cheat / anti-tamper focus; step-up rather than hard-block to protect conversion. |
| `health`   | Health / regulated           | `step_up` | Privacy + integrity focus for regulated data; steps up on elevated risk rather than hard-blocking legitimate access. |
| `media`    | Media / content protection   | `step_up` | Anti-piracy / content-protection focus; step-up on elevated risk. |

The packs live as embedded JSON under
`cmd/kseal-cli/internal/cli/packs_data/*.json`. Because they are pure data, the
defaults can evolve by editing those files alone — no server or client code
change.

## Pack format

Each pack is a single JSON object:

```json
{
  "id": "fintech",
  "vertical": "fintech",
  "name": "Fintech baseline",
  "description": "Strict, fail-closed posture for banking, payments, wallets.",
  "enforcement_mode": "block",
  "modules_enabled": ["integrity", "rasp", "attestation", "network", "anti-hooking", "environment"],
  "risk_thresholds": { "LOW_RISK": 15, "MEDIUM_RISK": 40, "HIGH_RISK": 70, "CRITICAL": 110 },
  "signal_weights": { "0": 50, "3": 45, "4": 65, "5": 80, "6": 60, "7": 55, "8": 50, "9": 70 }
}
```

| Field | Meaning |
|-------|---------|
| `id` | Stable, lowercase identifier used on the CLI (`pack show <id>`, `pack apply <id>`). |
| `vertical` | Human-readable vertical grouping. |
| `name` | Display name; also the default created-policy name (`pack-<id>` if `--name` is omitted). |
| `description` | One-line summary shown in `pack show`. |
| `enforcement_mode` | `observe` \| `step_up` \| `block`. |
| `modules_enabled` | The SDK module set this vertical expects (informational provenance; also feeds the MASVS report). |
| `risk_thresholds` | Score cutoffs keyed by `TrustLevel` name (`LOW_RISK`, `MEDIUM_RISK`, `HIGH_RISK`, `CRITICAL`). |
| `signal_weights` | Per-signal severity keyed by **risk-bit index** as a base-10 string in `0..63`. |

Packs are validated at load time against the same invariants the policy author
path enforces (valid enforcement mode, valid `TrustLevel` keys, bit indices in
`0..63`). An invalid embedded pack is treated as a build defect and fails fast,
so a composed policy is guaranteed to pass server validation. `signal_weights`
are emitted inside the policy `rules` object, and `risk_thresholds` into
`risk_thresholds`, matching the exact JSON the server stores — the scoring
tables round-trip through the existing parse path.

## Workflow

All commands follow the CLI's standard output conventions (`-o table|json`,
`--tenant`, `--dry-run`).

### List and inspect (offline, credential-free)

```bash
kseal policy pack list
kseal policy pack show fintech
```

`list` and `show` read only the embedded data — no server call, no credentials.

### Preview a pack against a tenant (`diff`)

```bash
kseal --tenant <tenant-id> policy pack diff fintech
kseal --tenant <tenant-id> policy pack diff fintech --app-id <app-id>
```

`diff` resolves the tenant's currently active policy (tenant-wide, or scoped to
`--app-id`) and reports the field-level changes the pack would introduce
(enforcement mode, thresholds, weights, module set). Read-only.

### Apply to one tenant (`apply`)

```bash
# Preview only — resolves and prints the diff, creates nothing:
kseal --tenant <tenant-id> policy pack apply fintech --dry-run

# Create a new policy version from the pack:
kseal --tenant <tenant-id> policy pack apply fintech --name fintech-2026q1

# Create and activate it:
kseal --tenant <tenant-id> policy pack apply fintech --activate
```

`apply` composes a `CreatePolicy` request from the pack and submits it. With
`--activate` the new version is activated via `ActivatePolicy`. `--dry-run`
prints the diff and exits without mutating anything.

### Apply across many tenants (`bulk-apply`)

```bash
# Tenants from a comma-separated list and/or a file (one id per line;
# blank lines and #-comments ignored):
kseal policy pack bulk-apply fintech \
  --tenants tenant-a,tenant-b \
  --tenants-file fleet.txt \
  --dry-run

kseal policy pack bulk-apply fintech --tenants-file fleet.txt --activate
```

`bulk-apply` is **idempotent by default**: a tenant whose active policy already
matches the pack is reported `unchanged` and skipped (use `--force` to apply
regardless). Each tenant is processed independently, so one tenant's failure is
captured in its result row (`status: error`) and never aborts the batch.
`--dry-run` reports the per-tenant plan (`would-apply` / `unchanged`) without
mutating anything. Per-tenant statuses:

| Status | Meaning |
|--------|---------|
| `created` / `activated` | A new policy version was created (and activated). |
| `unchanged` | Active policy already matches the pack; skipped (no `--force`). |
| `would-apply` | `--dry-run`: a non-idempotent change is planned. |
| `error` | This tenant failed; `error` carries the reason. Batch continues. |

## Notes & data considerations

- Packs only express what the existing policy schema supports
  (enforcement mode, thresholds, signal weights). `modules_enabled` is carried
  as provenance and reused by the MASVS report; it is not a server-enforced
  field.
- Diff/apply scoring reuses the server's `risk` package, so a previewed decision
  shift matches production exactly.

---

# MASVS evidence (`build masvs`)

The CLI can render an [OWASP MASVS](https://mas.owasp.org/MASVG/) evidence report
for a registered build:

```bash
kseal --tenant <tenant-id> build masvs <build-id>
kseal --tenant <tenant-id> -o json build masvs <build-id>
```

It reads the build via the existing `RegistryService.GetBuild` RPC (no new
server surface) and reports:

- **Build-hash proof** — the registered `build_hash`, app id, and version, i.e.
  the cryptographic provenance the server already attests.
- **Module / transform provenance** — parsed from the build `manifest`.
- **Per-category coverage** — each module is mapped (client-side) to the MASVS
  categories it contributes to (`STORAGE`, `CRYPTO`, `AUTH`, `NETWORK`,
  `PLATFORM`, `CODE`, `RESILIENCE`, `PRIVACY`), and the report lists covered
  categories and **gaps** (categories with no contributing module).

The module → MASVS mapping is client-side data (`cmd/kseal-cli/internal/cli/masvs.go`)
so it can evolve without a server change.

## Data gap (flagged, not worked around)

The existing RPCs do **not** expose a first-class MASVS verdict or per-control
test results — only the build-hash proof and the manifest. The report is
therefore an **honest, provenance-derived** view: coverage is inferred from
which hardening modules a build shipped, and the report always carries a note
stating this limitation. When the manifest is empty there is no module
provenance to map, and the report says so explicitly while still surfacing the
build-hash proof. Closing this gap (real per-control evidence) would require a
server change and is intentionally **not** done here.
