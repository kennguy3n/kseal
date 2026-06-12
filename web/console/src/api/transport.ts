import { createConnectTransport } from "@connectrpc/connect-web";
import type { Interceptor, Transport } from "@connectrpc/connect";

// Attaches the API key as a bearer token on every Connect request. The key is
// resolved lazily per call so it always reflects the current session (e.g. a
// re-login during the app lifetime) without rebuilding the transport.
export function authInterceptor(getApiKey: () => string | null): Interceptor {
  return (next) => async (req) => {
    const key = getApiKey();
    if (key) {
      req.header.set("Authorization", `Bearer ${key}`);
    }
    return next(req);
  };
}

export function createTransport(
  baseUrl: string,
  getApiKey: () => string | null,
): Transport {
  return createConnectTransport({
    baseUrl,
    interceptors: [authInterceptor(getApiKey)],
  });
}
