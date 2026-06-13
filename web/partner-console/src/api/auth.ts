// Partner / MSSP session: the API key, the managed tenant set, and the API base
// URL.
//
// Unlike the single-tenant admin console, a partner operates across many
// tenants, so the session carries a list of tenant ids. The API key is the
// bearer credential attached to every Connect call and must be authorized for
// those tenants by the control plane (it is never logged). Persisted to
// localStorage so a reload stays signed in.

import { defaultApiBaseUrl } from "../config";

export interface Session {
  apiKey: string;
  tenantIds: string[];
  apiBaseUrl: string;
}

const STORAGE_KEY = "kseal.partner.session.v1";

/** Normalizes a tenant-id list: trims, drops blanks, de-dups, preserves order. */
export function normalizeTenantIds(ids: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of ids) {
    const id = raw.trim();
    if (id.length === 0 || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

/** Parses a free-text tenant list (newline- or comma-separated) into ids. */
export function parseTenantIds(text: string): string[] {
  return normalizeTenantIds(text.split(/[\n,]/));
}

function readStorage(): Session | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<Session>;
    const tenantIds = Array.isArray(parsed.tenantIds)
      ? normalizeTenantIds(parsed.tenantIds.filter((t): t is string => typeof t === "string"))
      : [];
    // Require a non-empty key and at least one tenant: an empty credential or
    // empty fleet (e.g. tampered localStorage) would load a "signed in" session
    // whose RPCs all fail or show nothing. Treat it as logged out instead.
    if (
      typeof parsed.apiKey !== "string" ||
      parsed.apiKey.length === 0 ||
      tenantIds.length === 0
    ) {
      return null;
    }
    return {
      apiKey: parsed.apiKey,
      tenantIds,
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
