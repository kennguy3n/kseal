// Console session: the API key, the active tenant, and the API base URL.
//
// The API key is the bearer credential attached to every Connect call. We keep
// it in localStorage so a reload stays signed in; it is never logged. Tenant id
// is required because every RPC is tenant-scoped (see proto request messages).

import { defaultApiBaseUrl } from "../config";

export interface Session {
  apiKey: string;
  tenantId: string;
  apiBaseUrl: string;
}

const STORAGE_KEY = "kseal.console.session.v1";

function readStorage(): Session | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<Session>;
    // Require non-empty credentials: an empty apiKey/tenantId (e.g. from
    // tampered localStorage) would load a "signed in" session whose RPCs all
    // fail auth. Treat it as logged out instead.
    if (
      typeof parsed.apiKey !== "string" ||
      parsed.apiKey.length === 0 ||
      typeof parsed.tenantId !== "string" ||
      parsed.tenantId.length === 0
    ) {
      return null;
    }
    return {
      apiKey: parsed.apiKey,
      tenantId: parsed.tenantId,
      apiBaseUrl:
        typeof parsed.apiBaseUrl === "string" && parsed.apiBaseUrl.length > 0
          ? parsed.apiBaseUrl
          : defaultApiBaseUrl(),
    };
  } catch {
    return null;
  }
}

export function loadSession(): Session | null {
  return readStorage();
}

export function saveSession(session: Session): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

export function clearSession(): void {
  localStorage.removeItem(STORAGE_KEY);
}
