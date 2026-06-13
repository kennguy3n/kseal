# kseal partner / MSSP console

A read-only React/Vite app for partners and managed-security providers (MSSPs)
who operate **many** kseal tenants. It computes fleet-wide rollups **entirely in
the browser** over the existing per-tenant `QueryService` reads — there is no
fleet/partner RPC and no server change.

See [`docs/mssp-console.md`](../../docs/mssp-console.md) for what the console
shows and exactly how each rollup is derived (including the documented data gaps).

## Develop

```bash
npm install
npm run proto:gen     # regenerate the typed Connect client from //proto
npm run dev           # http://localhost:5173
npm run lint
npm test              # vitest (rollup logic + page rendering)
npm run build         # tsc -b && vite build
```

## Sign in

The login form takes:

- **API base URL** — origin of the kseal server (default `http://localhost:8080`).
- **Tenant IDs** — the managed fleet, one per line or comma-separated.
- **Partner API key** — a bearer credential authorized for those tenants. It is
  attached to every Connect call and is never logged.

The session (key + tenant set + base URL) is persisted to `localStorage`; the
key is held only in memory for the transport interceptor.

## Runtime configuration (NoOps)

Identical to `web/console`: a single prebuilt image is pointed at any API origin
at deploy time via the `KSEAL_API_BASE_URL` container env, which
`docker-entrypoint.sh` renders into `/env.js` (and tightens the CSP
`connect-src` to that origin). When unset, the app falls back to the build-time
`VITE_KSEAL_API_BASE_URL`.

## How rollups work

`src/lib/rollup.ts` holds the pure aggregation logic (no network, no React) so
it is unit-testable in isolation. `src/hooks/fleet.ts` fans out one cached query
per tenant, awaits overview + trust-session reads independently (so a single
failing read degrades that stat instead of dropping the tenant), and feeds the
snapshots into `computeFleetRollup`.
