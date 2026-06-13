import {
  useCallback,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { Transport } from "@connectrpc/connect";
import { useQueryClient } from "@tanstack/react-query";
import {
  clearSession,
  loadSession,
  saveSession,
  type Session,
} from "../api/auth";
import { createTransport } from "../api/transport";
import { createClients } from "../api/clients";
import { AuthContext, type AuthContextValue } from "./useAuth";

export function AuthProvider({
  children,
  transport,
}: {
  children: ReactNode;
  // Optional transport override for tests (in-memory router transport).
  transport?: Transport;
}) {
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const queryClient = useQueryClient();

  // Keep the latest API key in a ref so the transport interceptor always reads
  // the current credential without rebuilding the transport on every change.
  const apiKeyRef = useRef<string | null>(session?.apiKey ?? null);
  apiKeyRef.current = session?.apiKey ?? null;

  const baseUrl = session?.apiBaseUrl ?? "";

  const clients = useMemo(() => {
    const t = transport ?? createTransport(baseUrl, () => apiKeyRef.current);
    return createClients(t);
  }, [baseUrl, transport]);

  const login = useCallback(
    (next: Session) => {
      // Clear any residual cache before adopting the new session (symmetric
      // with logout) so a login never serves another session's cached data.
      queryClient.clear();
      saveSession(next);
      setSession(next);
    },
    [queryClient],
  );

  const logout = useCallback(() => {
    clearSession();
    setSession(null);
    // Drop all cached server state so a subsequent login (even as the same
    // tenant with a different key/permissions) never shows stale data.
    queryClient.clear();
  }, [queryClient]);

  const value = useMemo<AuthContextValue>(
    () => ({ session, clients, login, logout }),
    [session, clients, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
