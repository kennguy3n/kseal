// Resolves the kseal API base URL with a clear precedence so the same build
// works in local dev and as a prebuilt, deploy-time-configurable image:
//
//   1. window.__KSEAL_ENV__.apiBaseUrl  — injected at container start (NoOps;
//      see public env.js / docker-entrypoint.sh) for prebuilt images.
//   2. import.meta.env.VITE_KSEAL_API_BASE_URL — Vite-inlined at build time.
//   3. http://localhost:8080 — local dev default (matches docker-compose).

export interface KsealRuntimeEnv {
  apiBaseUrl?: string;
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
