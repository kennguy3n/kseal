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

type Listener = (session: Session | null) => void;
const listeners = new Set<Listener>();

function readStorage(): Session | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<Session>;
    if (
      typeof parsed.apiKey !== "string" ||
      typeof parsed.tenantId !== "string"
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
  for (const l of listeners) l(session);
}

export function clearSession(): void {
  localStorage.removeItem(STORAGE_KEY);
  for (const l of listeners) l(null);
}

export function subscribe(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
