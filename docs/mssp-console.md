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
- **Fleet health**: a stacked at-a-glance breakdown of how many tenants fall in
  each health band (At risk / Watch / Healthy / Unknown).
- **Recent signal activity (24h)**: a sparkline of fleet-wide risk events,
  derived from each tenant's recent events, with the high/critical share
  overlaid.
- **Enforcement pressure**: high-risk session rate, step-up session rate
  (proxy), and attestation-failure rate (see *How rollups are computed* for the
  exact definitions and the data gap they work around).
- **Trust-level distribution**: fleet-wide session counts per `TrustLevel`.
- A **degraded-data notice** when one or more tenants returned incomplete reads.
- A **Tenant health** preview of the tenants needing the most attention, linking
  to the full Tenants view, plus CSV/JSON **export** of the fleet.

**Tenants** (`/tenants`)

- One row per managed tenant, **sorted worst-first** by a derived health score
  (every column is sortable), so the tenants needing attention surface at the
  top.
- Per tenant: health band (Healthy / Watch / At risk / Unknown), score, primary
  region, app count, 24h events, sessions, high-risk rate, attestation-failure
  rate, and a recent-activity sparkline.
- **Quick filters & search**: free-text search across tenant id and region,
  health-band chips, a region selector, and a *breaching-only* toggle.
- **Saved views**: name and persist a filter + sort + threshold combination and
  re-apply it later; the working state itself also persists across reloads.
- **Alert thresholds**: client-side bounds (min health score, max high-risk %,
  max attestation-failure %) that highlight breaching tenants. Purely
  presentational — no server change.
- **Export**: CSV (per-tenant rows) or JSON (rows + fleet totals) of the current
  filtered view, for reporting.
- A tenant whose reads partially or fully failed is still listed, with the
  failure reason shown inline rather than being dropped.

**Tenant drill-down** (`/tenants/:tenantId`)

- Fleet → tenant → signal: KPIs, derived health, enforcement pressure, and
  trust-level distribution for a single tenant.
- A keyset-paginated **signals** table (`ListEvents`) of the tenant's risk
  events — time, signal type, fused risk level, app, and region — filterable by
  risk level. Reuses the cached fleet read for the header so opening a tenant is
  instant.
- Tenants outside the operator's managed set render a clear "not in your fleet"
  message instead of issuing a read.

## How rollups are computed (client-side)

There is **no fleet/partner RPC**. The server exposes only per-tenant,
tenant-scoped reads, so the console fetches each managed tenant independently and
aggregates in the browser.

Per tenant, over the existing `QueryService`:

- `GetTenantOverview` → `app_count`, `build_count`, `active_policy_count`,
  `webhook_count`, `events_last_24h`, and `recent_events` (projected to the
  console's `SignalRecord` for sparklines, region derivation, and drill-down).
- `ListEvents` (drill-down only) → the tenant's risk events, keyset-paginated
  and optionally filtered by risk level.
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

Banded as: `healthy` (≥ 80), `watch` (50–79), `at-risk` (< 50). Because the score
is derived **entirely from trust-session / attestation rates**, a tenant is only
health-assessable when it has some trust signal (any sessions or tokens). A
tenant with an `error` status, or one with apps registered but **zero sessions
and zero tokens** (e.g. newly onboarded, no runtime traffic yet), is scored 0 and
banded **`unknown`** — so it surfaces for the operator rather than silently
counting as a clean `healthy` 100.

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

## Client-side view state (filters, saved views, thresholds, theme)

All operator preferences are **client-side only** — no server, no mutation —
and live in `localStorage`, defensively validated on load so tampered or stale
storage degrades to defaults rather than crashing:

- `kseal.partner.viewstate.v1` — the working filter / sort / thresholds.
- `kseal.partner.views.v1` — named saved views.
- `kseal.partner.theme.v1` — the color-theme preference (`system` / `light` /
  `dark`); `system` follows the OS and live-updates.

The pure logic is split for testability: `lib/filter.ts` (filter/search/sort),
`lib/thresholds.ts` (breach evaluation), `lib/export.ts` (CSV/JSON
serialization), `lib/events.ts` (signal bucketing + region derivation),
`lib/views.ts` (persistence + sanitization), and `lib/theme.ts` (theme
resolution). `hooks/useFleetView.ts` ties view state to a rollup; the views
render the derived, filtered list.

## Accessibility & theming

The console targets **WCAG AA**: a skip-to-content link, semantic landmarks,
labelled controls, `aria-sort` on sortable headers, `aria-pressed` quick
filters, visible keyboard focus rings, `role="img"` + textual summaries on
charts, and reduced-motion support. Colors flow through semantic design tokens
(`src/index.css`) so light/dark is a single class swap on `<html>`; the app
ships dark by default and reconciles to the stored/system preference before
first paint.

## Sign-in

The login form takes the API base URL, the managed tenant IDs (one per line or
comma-separated), and a partner API key authorized for those tenants. The
session is persisted to `localStorage`; the key is kept in memory for the
transport interceptor. See `web/partner-console/README.md` for dev/build/test and
runtime-configuration details.
