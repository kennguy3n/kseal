import { createContext, useContext } from "react";
import type { Session } from "../api/auth";
import type { KsealClients } from "../api/clients";

export interface AuthContextValue {
  session: Session | null;
  clients: KsealClients;
  login: (session: Session) => void;
  logout: () => void;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}

export function useClients(): KsealClients {
  return useAuth().clients;
}

export function useSession(): Session {
  const { session } = useAuth();
  if (!session) throw new Error("useSession requires an authenticated session");
  return session;
}
