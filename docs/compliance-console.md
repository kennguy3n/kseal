# kseal — Compliance & Ops Console

The kseal admin console (`web/console/`) is the tenant-scoped, self-service UI
for the control plane. This document covers the **compliance & operations**
surface added on top of the existing Dashboard / Apps / Policies / Events /
Webhooks / SIEM pages:

| Section | Route | Purpose |
|---|---|---|
| Audit trail | `/audit` | Paginated, filterable view of the hash-chained control-plane mutation log. |
| Data processing | `/data-processing` | Per-tenant register of what data each app/SDK processes (category, purpose, retention, lawful basis). |
| MASVS evidence | `/masvs` | OWASP MASVS coverage for a release, derived from the registered build-proof manifest. |
| Kill switch | `/kill-switch` | View current state and request a **signed** enable/disable of protection enforcement. |
| Canary monitor | `/canary` | Staged-rollout percentage, cohort health and auto-rollback status. |

These map to the [feature parity matrix](./feature-parity-matrix.md) rows
*Audit trail / data-processing registry*, *Auto-generated MASVS evidence
report*, *Signed kill switch (remote disable)*, and *Canary rollout +
auto-rollback*, bringing the console toward enterprise-compliance-console parity
with AppSealing/DoveRunner, Appdome, Guardsquare, Promon and Zimperium.

## Data sources

The console reads everything over the authenticated Connect-Web transport
(`src/api/transport.ts`); every request carries `tenant_id` and react-query
cache keys are tenant-scoped, so caches never bleed across the tenant boundary.

Two classes of data back these views:

1. **Canonical, available today.** The **MASVS evidence** view is computed
   entirely client-side from `RegistryService.ListBuilds` build manifests — the
   same derivation the CLI report generator does
   (`cmd/kseal-cli/internal/cli/masvs.go`), ported in `src/lib/masvs.ts`. No new
   server capability is required; it works against `main`.

2. **Console-local RPCs (graceful degradation).** The **audit trail**,
   **data-processing registry**, **kill switch** and **canary monitor** read
   from RPCs that are being added to the canonical server by WS-K. Until those
   land, the console talks to them through a **console-local generated client**
   and renders a clean *"not available yet"* state when the server returns
   `UNIMPLEMENTED`/`UNAVAILABLE`.

### Console-local proto client

Because the canonical `//proto` module is owned by another component and must
not be modified here, the console-local RPCs live in their own module under
`web/console/`:

```
web/console/
  proto-local/kseal/consolelocal/v1/compliance.proto   # source of truth (local)
  buf.gen.local.yaml                                    # codegen template
  scripts/gen-proto-local.sh                            # npm run proto:gen:local
  src/gen-local/…                                       # committed generated client
```

- The package is `kseal.consolelocal.v1` (deliberately distinct from `kseal.v1`)
  so generated symbols never collide with the canonical client in `src/gen/`.
- Generation is fully separate from the canonical `npm run proto:gen` (which
  uses `clean: true` on `src/gen`), so regenerating one never clobbers the other.
- `src/gen-local/` is committed, mirroring `src/gen/`, so the Docker build
  (context = `web/console/` only) needs no proto access.

Detection of the degraded state is centralized in `src/lib/availability.ts`
(`isUnavailableError`, `retryUnlessUnavailable`); the
[`UnavailableNotice`](../web/console/src/components/ui.tsx) component renders it.

**Migration:** once WS-K's RPCs merge into the canonical module, the parent
re-points these hooks at the canonical `src/gen` client and deletes
`proto-local/` + `src/gen-local/`. The view code does not change.

## Views

### Audit trail (`/audit`)
- Tenant-scoped, newest-first, keyset-paginated (`Load more`).
- Filters: actor, resource type, action keys (comma-separated), time range.
- Renders the per-entry chain hash and surfaces a **chain-verification warning**
  when the server reports a broken link (`chain_verified=false`), so tampering is
  visible rather than silent.
- Metadata is rendered as a deterministic, sorted `key=value` list — only the
  small non-PII context map the server returns.

### Data-processing registry (`/data-processing`)
- Scoped to all apps + tenant-wide, or a single app.
- Each record shows category, purpose, retention, lawful basis, a
  personal-data flag, and the concrete (non-PII) field names processed.

### MASVS evidence (`/masvs`)
- Pick an app and a build; the report shows covered/total MASVS categories, the
  build-hash proof, applied transforms, gaps, and honest notes about the limits
  of build-manifest-derived evidence.
- Driven by real manifest data, never a static template (mirrors the CLI/report
  generator semantics).

### Kill switch (`/kill-switch`)
- Shows the current signed state (armed/disabled), who changed it, when, the
  signing key id, and the recorded reason.
- A change is a **two-step, fail-safe action**: the operator must enter a reason
  and explicitly confirm before a signed change is requested. The console only
  *requests* the change — **all signing and authority are server-side** (WS-K).
- A successful change invalidates both the kill-switch state and the audit trail
  (the change is itself an audited mutation).

### Canary monitor (`/canary`)
- Lists staged rollouts with rollout percentage (visualized), cohort health,
  auto-rollback armed/triggered status, canary vs. baseline error rate, cohort
  size, and the rollback reason when auto-rolled back.

## Privacy & security

- **No PII in the UI or logs.** The data-processing register surfaces field
  *names* and a personal-data flag, not values; audit metadata is the server's
  minimized non-PII context map; the API key is never logged.
- **Tenant isolation.** Every query is `tenant_id`-scoped and cache keys include
  the tenant id; logout/login clears the query cache.
- **Fail-safe by default.** New views are additive and read-only except the
  kill-switch request, which is gated behind explicit confirmation + a required
  reason and degrades closed (no action offered) when the capability is
  unavailable.

## Testing

Each view has component tests (`src/pages/*.test.tsx`) driven by an in-memory
Connect router transport (`createRouterTransport`), plus unit tests for the
MASVS derivation (`src/lib/masvs.test.ts`) and the availability helpers
(`src/lib/availability.test.ts`). The graceful-degradation path is covered by
asserting the *"not available yet"* state when the console-local service is
unregistered (i.e. the server returns `UNIMPLEMENTED`).

```bash
cd web/console
npm install
npm run lint
npm test
npm run proto:gen:local   # regenerate the console-local client (needs buf)
```
