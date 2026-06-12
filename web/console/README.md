# kseal console

Minimal React dashboard for the kseal control plane. Talks to the kseal server
over **Connect-Web** using clients generated from the canonical protobufs.

## Stack

- Vite + React 18 + TypeScript
- `react-router-dom` for routing
- `@tanstack/react-query` for server-state caching (tenant-scoped query keys)
- `@connectrpc/connect-web` transport with a bearer-token auth interceptor
- Tailwind CSS

## Pages

| Route        | Purpose                                                        |
| ------------ | -------------------------------------------------------------- |
| `/login`     | Enter API base URL, tenant ID and API key; stored locally.     |
| `/`          | Tenant overview: app/webhook counts, recent events, trust stats|
| `/apps`      | Registered apps (platform, package id, status).                |
| `/apps/:id`  | App detail: builds, active policy, recent events.              |
| `/policies`  | View/author policies and activate one.                         |
| `/events`    | Event list filtered by type, risk level and time range.        |
| `/webhooks`  | List / create / delete webhooks.                               |

## Develop

```bash
npm ci
npm run dev        # http://localhost:5173, talks to http://localhost:8080
npm run build      # type-check + production bundle
npm run lint
npm test           # Vitest + React Testing Library
```

## Auth

The API key entered at login is persisted in `localStorage` and attached as
`Authorization: Bearer <key>` to every Connect call by an interceptor
(`src/api/transport.ts`). It is never logged. Every RPC is tenant-scoped via the
`tenant_id` request field, and react-query cache keys include the tenant id so
caches never bleed across tenants.

## Connect client codegen

The canonical schemas live in `//proto` (their own buf module) and are owned by
another component; this package must not modify them. `npm run proto:gen` runs
`buf generate` directly against that module into `src/gen/`:

```bash
npm run proto:gen   # regenerates src/gen from //proto
```

`buf.gen.yaml` and `scripts/gen-proto.sh` drive this. The generated output in
`src/gen/` is committed so the Docker build (whose context is only
`web/console/`) does not need access to `//proto`.

### Read surface — `QueryService`

The Dashboard and Events pages read derived data-plane state — stored risk
events, tenant overview counters, and trust-session statistics — via
`QueryService` (`ListEvents`, `GetTenantOverview`, `GetTrustSessionStats`),
defined in the canonical `//proto/kseal/v1/query.proto` +
`query_service.proto` and implemented server-side with tenant-isolated,
keyset-paginated queries. The pages render real data; a thin `ErrorNotice`
fallback covers transient RPC failures.

### Pagination

The Apps, App-detail builds, and Events lists are keyset-paginated. Each hook
(`useApps`, `useBuilds`, `useEvents`) is a `useInfiniteQuery` that sends the
server's `next_page_token` back as the `page_token` of the next request and a
"Load more" control appends the next page. When the server returns an empty
`next_page_token` the control disappears, so the views never silently truncate.

## Runtime configuration (NoOps)

`VITE_KSEAL_API_BASE_URL` is inlined at build time (default
`http://localhost:8080`). The Docker image additionally supports **deploy-time**
override without a rebuild:

- `docker-entrypoint.sh` runs at container start (via nginx's
  `/docker-entrypoint.d`) and renders `/env.js` from `KSEAL_API_BASE_URL`.
- `index.html` loads `/env.js` before the app; `src/config.ts` prefers
  `window.__KSEAL_ENV__.apiBaseUrl`, then the inlined build var, then the local
  default.
- `/env.js` is served `no-store`; hashed assets are cached immutably.

```bash
docker build -t kseal-console .
docker run -p 8080:80 -e KSEAL_API_BASE_URL=https://api.example.com kseal-console
```
