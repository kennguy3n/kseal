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

1. **Derived client-side.** The **MASVS evidence** view is computed entirely
   client-side from `RegistryService.ListBuilds` build manifests — the same
   derivation the CLI report generator does
   (`cmd/kseal-cli/internal/cli/masvs.go`), ported in `src/lib/masvs.ts`. No
   compliance RPC is required.

2. **Canonical `ComplianceService` (graceful degradation).** The **audit
   trail**, **data-processing registry**, **kill switch** and **canary monitor**
   read the canonical `kseal.v1.ComplianceService`
   (`//proto/kseal/v1/compliance.proto` + `compliance_service.proto`). A server
   build that predates the service returns `UNIMPLEMENTED`/`UNAVAILABLE`, which
   each view renders as a clean *"not available yet"* state rather than an error.

### Canonical compliance client

The console consumes the generated `ComplianceService` client from `src/gen/`,
produced by the standard `npm run proto:gen` against the canonical `//proto`
module — there is no console-local proto module. Notable shape mappings the
views/hooks (`src/hooks/compliance.ts`) apply:

- Audit events use canonical field names (`seq`, `created_at`, `actor_key_id`,
  `hash`, `prev_hash`); chain integrity is verified through the dedicated
  `VerifyAuditChain` RPC rather than a per-page flag.
- The data-processing registry is unpaginated (`GetDataProcessingRegistry`);
  app filtering is applied client-side.
- Kill-switch state is a `KillSwitchCommand` enum (`ENABLE`/`DISABLE`); issuance
  is the signed `IssueKillSwitch` control-plane RPC.
- Canary status is a single `GetCanaryStatus` per app (`NotFound` ⇒ no rollout),
  with a `CanaryState` enum (`ACTIVE`/`PROMOTED`/`ROLLED_BACK`).

Detection of the degraded state is centralized in `src/lib/availability.ts`
(`isUnavailableError`, `retryUnlessUnavailable`); the
[`UnavailableNotice`](../web/console/src/components/ui.tsx) component renders it.

## Views

### Audit trail (`/audit`)
- Tenant-scoped, newest-first, keyset-paginated (`Load more`).
- Filters: action, resource type, time range.
- Renders the per-entry chain hash and surfaces a **chain-verification warning**
  when `VerifyAuditChain` reports a broken link (`intact=false`), so tampering is
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
- Shows the current effective command (armed/disabled), the active signed
  record's version, signing key id, and recorded reason.
- A change is a **two-step, fail-safe action**: the operator must enter a reason
  and explicitly confirm before a signed change is requested. The console only
  *requests* the change — **all signing and authority are server-side** (WS-K).
- A successful change invalidates both the kill-switch state and the audit trail
  (the change is itself an audited mutation).

### Canary monitor (`/canary`)
- Shows the staged rollout for the selected scope: rollout percentage
  (visualized), `CanaryState` (active/promoted/rolled back), block rate vs.
  rollback threshold, sample count, and the last event when auto-rolled back.

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
asserting the *"not available yet"* state when `ComplianceService` is
unregistered (i.e. the server returns `UNIMPLEMENTED`).

```bash
cd web/console
npm install
npm run lint
npm test
npm run proto:gen   # regenerate the canonical client (needs buf)
```
