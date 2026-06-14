/// <reference types="vitest/config" />
import process from "node:process";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Backend the dev server proxies Connect RPCs to. Override when the API runs
// somewhere other than the docker-compose default (e.g. a remote host).
const DEV_API_PROXY_TARGET =
  process.env.KSEAL_DEV_API_PROXY_TARGET || "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Connect RPCs are POSTed to /<package>.<Service>/<Method> (all kseal
    // services live under the "kseal." package prefix). Proxying that namespace
    // to the backend keeps the browser talking only to its own origin in dev,
    // so there is no CORS preflight and no failure when the dev server's
    // host/port (e.g. 127.0.0.1:5174) differs from the server's CORS allowlist.
    // The console's same-origin default base URL (src/config.ts) routes here.
    proxy: {
      "^/kseal\\.": {
        target: DEV_API_PROXY_TARGET,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/gen/**", "src/**/*.test.{ts,tsx}", "src/test/**"],
    },
  },
});
