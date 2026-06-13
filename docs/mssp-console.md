# Partner / MSSP console

The partner console (`web/partner-console`) is a separate, **read-only**
React/Vite app for partners and managed-security providers (MSSPs) who operate
**many** kseal tenants. It gives a fleet-wide view — trust sessions, event
volumes, enforcement pressure, and per-tenant health — without any
partner-specific server endpoint.

It is a sibling of the single-tenant admin console (`web/console`) and reuses its
conventions: the generated Connect `QueryService` client, the bearer-token
request/auth pattern, the runtime-config (`env.js`) NoOps deploy model, and the
Tailwind UI kit.

## What it shows

**Fleet overview** (`/`)

- Headline stats: managed tenant count, total apps, total events (24h), total
  trust sessions — summed across the fleet.
- **Enforcement pressure**: high-risk session rate, step-up session rate
  (proxy), and attestation-failure rate (see *How rollups are computed* for the
  exact definitions and the data gap they work around).
- **Trust-level distribution**: fleet-wide session counts per `TrustLevel`.
- A **degraded-data notice** when one or more tenants returned incomplete reads.

**Tenants** (`/tenants`) and the fleet-overview health table

- One row per managed tenant, **sorted worst-first** by a derived health score,
  so the tenants needing attention surface at the top.
- Per tenant: health band (Healthy / Watch / At risk / Unknown), score, app
  count, 24h events, sessions, high-risk rate, and attestation-failure rate.
- A tenant whose reads partially or fully failed is still listed, with the
  failure reason shown inline rather than being dropped.

## How rollups are computed (client-side)

There is **no fleet/partner RPC**. The server exposes only per-tenant,
tenant-scoped reads, so the console fetches each managed tenant independently and
aggregates in the browser.

Per tenant, over the existing `QueryService`:

- `GetTenantOverview` → `app_count`, `build_count`, `active_policy_count`,
  `webhook_count`, `events_last_24h`.
- `GetTrustSessionStats` → `total_sessions`, `tokens_issued`,
  `attestations_failed`, and `sessions_by_trust_level` (a map keyed by the short
  `TrustLevel` names `TRUSTED`, `LOW_RISK`, `MEDIUM_RISK`, `HIGH_RISK`,
  `CRITICAL`).

The fan-out lives in `src/hooks/fleet.ts`: one **cached query per tenant**, run
in parallel, each awaiting its two reads independently (`Promise.allSettled`) so
a single failing read degrades only that stat (`status: "partial"`) instead of
dropping the tenant, and a tenant whose reads all fail becomes `status: "error"`
but is still listed for triage.

The pure aggregation lives in `src/lib/rollup.ts` (no network, no React, fully
unit-tested):

- **Totals** are simple sums; a missing stat contributes `0`, and unknown
  trust-level keys are ignored.
- **`attestationFailureRate`** = `attestations_failed / tokens_issued` (0 when
  no tokens).
- **`highRiskSessionRate`** = `(HIGH_RISK + CRITICAL) / total_sessions`.
- **`mediumRiskSessionRate`** = `MEDIUM_RISK / total_sessions` — used as a
  **step-up proxy** (see data gap below).
- All rates are guarded against divide-by-zero and clamped to `[0, 1]`.

### Per-tenant health score

Each tenant gets a 0–100 health score (higher = healthier):

```
penalty = 0.6 * highRiskRate + 0.3 * attestationFailureRate + 0.1 * mediumRiskRate
score   = round(clamp(1 - penalty, 0, 1) * 100)
```

Banded as: `healthy` (≥ 80), `watch` (50–79), `at-risk` (< 50). A tenant with no
usable data or an `error` status is scored 0 and banded **`unknown`**, so it
surfaces for the operator rather than silently counting as healthy.

## Data gap (flagged, not worked around)

The existing RPCs do **not** expose explicit per-decision **block / step-up**
counts. Rather than add a server RPC, the console approximates fleet enforcement
pressure from data that *is* exposed:

- **High-risk session rate** (`HIGH_RISK + CRITICAL` share) stands in for block
  pressure.
- **Step-up session rate** uses the `MEDIUM_RISK` share as a proxy.
- **Attestation-failure rate** is exact (`attestations_failed / tokens_issued`).

These are labelled as proxies in the UI. Exact block/step-up decision counts
would require a server change and are intentionally not added here.

## Performance & multi-tenant notes

- **No launch-time network calls**: the app boots from a persisted session and
  only issues reads once authenticated.
- Per-tenant queries are **cached and parallel**, with a short `staleTime`, so a
  large managed fleet loads incrementally and re-renders as results arrive; a
  manual **Refresh** re-fetches the fleet.
- All reads are tenant-scoped by `tenant_id`; the console never assumes
  cross-tenant data and degrades gracefully per tenant. The partner API key is
  attached as a bearer token per request and is **never logged**.

## Sign-in

The login form takes the API base URL, the managed tenant IDs (one per line or
comma-separated), and a partner API key authorized for those tenants. The
session is persisted to `localStorage`; the key is kept in memory for the
transport interceptor. See `web/partner-console/README.md` for dev/build/test and
runtime-configuration details.
