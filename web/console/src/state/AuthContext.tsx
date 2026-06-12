import {
  useCallback,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { Transport } from "@connectrpc/connect";
import {
  clearSession,
  loadSession,
  saveSession,
  type Session,
} from "../api/auth";
import { createTransport } from "../api/transport";
import { createClients } from "../api/clients";
import { AuthContext, type AuthContextValue } from "./authContext";

export function AuthProvider({
  children,
  transport,
}: {
  children: ReactNode;
  // Optional transport override for tests (in-memory router transport).
  transport?: Transport;
}) {
  const [session, setSession] = useState<Session | null>(() => loadSession());

  // Keep the latest API key in a ref so the transport interceptor always reads
  // the current credential without rebuilding the transport on every change.
  const apiKeyRef = useRef<string | null>(session?.apiKey ?? null);
  apiKeyRef.current = session?.apiKey ?? null;

  const baseUrl = session?.apiBaseUrl ?? "";

  const clients = useMemo(() => {
    const t = transport ?? createTransport(baseUrl, () => apiKeyRef.current);
    return createClients(t);
  }, [baseUrl, transport]);

  const login = useCallback((next: Session) => {
    saveSession(next);
    setSession(next);
  }, []);

  const logout = useCallback(() => {
    clearSession();
    setSession(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({ session, clients, login, logout }),
    [session, clients, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
