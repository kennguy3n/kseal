// Resolves the kseal API base URL with a clear precedence so the same build
// works in local dev and as a prebuilt, deploy-time-configurable image:
//
//   1. window.__KSEAL_ENV__.apiBaseUrl  — injected at container start (NoOps;
//      see public env.js / docker-entrypoint.sh) for prebuilt images.
//   2. import.meta.env.VITE_KSEAL_API_BASE_URL — Vite-inlined at build time.
//   3. http://localhost:8080 — local dev default (matches docker-compose).

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

const DEFAULT_API_BASE_URL = "http://localhost:8080";

function normalize(url: string): string {
  return url.replace(/\/+$/, "");
}

export function defaultApiBaseUrl(): string {
  const runtime =
    typeof window !== "undefined" ? window.__KSEAL_ENV__?.apiBaseUrl : undefined;
  const inlined = import.meta.env.VITE_KSEAL_API_BASE_URL;
  const chosen = runtime || inlined || DEFAULT_API_BASE_URL;
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
