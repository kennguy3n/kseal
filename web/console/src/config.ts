// Resolves the kseal API base URL with a clear precedence so the same build
// works in local dev and as a prebuilt, deploy-time-configurable image:
//
//   1. window.__KSEAL_ENV__.apiBaseUrl  — injected at container start (NoOps;
//      see public env.js / docker-entrypoint.sh) for prebuilt images.
//   2. import.meta.env.VITE_KSEAL_API_BASE_URL — Vite-inlined at build time.
//   3. the page's own origin (same-origin) — the safe default.
//
// The same-origin fallback is deliberate. A hardcoded cross-origin host like
// http://localhost:8080 makes the browser issue cross-origin requests, which
// only succeed if the server's CORS allowlist (KSEAL_CORS_ORIGINS) names the
// console's exact origin — host AND port. A mismatch (e.g. the dev server on
// 127.0.0.1:5174 vs an allowlist of http://localhost:5173) is silently blocked
// by the browser and surfaces as "Failed to fetch". Defaulting to same-origin
// avoids that entire class: in local dev the Vite dev-server proxy (see
// vite.config.ts) forwards the Connect RPC paths to the backend, and a typical
// single-origin deployment serves the console and API behind one host. Point
// elsewhere with VITE_KSEAL_API_BASE_URL / window.__KSEAL_ENV__.apiBaseUrl.

export interface KsealRuntimeEnv {
  apiBaseUrl?: string;
  // Optional base URL for product documentation (quickstart, SDK integration,
  // compliance guides) linked from the console. Deploy-time configurable so an
  // operator can point at their own docs mirror; falls back to the public docs.
  docsBaseUrl?: string;
}

declare global {
  interface Window {
    __KSEAL_ENV__?: KsealRuntimeEnv;
  }
}

function normalize(url: string): string {
  return url.replace(/\/+$/, "");
}

// The console's own origin (e.g. "http://127.0.0.1:5174"). Requests sent here
// are same-origin, so the browser performs no CORS preflight; in dev the Vite
// proxy forwards them to the backend. Empty only in non-browser contexts.
function sameOriginBaseUrl(): string {
  return typeof window !== "undefined" ? window.location.origin : "";
}

export function defaultApiBaseUrl(): string {
  const runtime =
    typeof window !== "undefined" ? window.__KSEAL_ENV__?.apiBaseUrl : undefined;
  const inlined = import.meta.env.VITE_KSEAL_API_BASE_URL;
  const chosen = runtime || inlined || sameOriginBaseUrl();
  return normalize(chosen);
}

// Public documentation tree (GitHub). Resolved with the same precedence as
// defaultApiBaseUrl so both follow one contract:
//
//   1. window.__KSEAL_ENV__.docsBaseUrl — injected at container start (NoOps)
//      so an operator can point at their own docs mirror without a rebuild.
//   2. import.meta.env.VITE_KSEAL_DOCS_BASE_URL — Vite-inlined at build time
//      (e.g. a local docs server during development).
//   3. the public GitHub docs tree — universal default.
const DEFAULT_DOCS_BASE_URL =
  "https://github.com/kennguy3n/kseal/blob/main/docs";

export function docsBaseUrl(): string {
  const runtime =
    typeof window !== "undefined"
      ? window.__KSEAL_ENV__?.docsBaseUrl
      : undefined;
  const inlined = import.meta.env.VITE_KSEAL_DOCS_BASE_URL;
  return normalize(runtime || inlined || DEFAULT_DOCS_BASE_URL);
}
