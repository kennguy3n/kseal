import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../state/authContext";
import { defaultApiBaseUrl } from "../config";

interface LocationState {
  from?: string;
}

export function LoginPage() {
  const { session, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as LocationState | null)?.from ?? "/";

  const [apiBaseUrl, setApiBaseUrl] = useState(
    session?.apiBaseUrl ?? defaultApiBaseUrl(),
  );
  const [tenantId, setTenantId] = useState(session?.tenantId ?? "");
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);

  if (session) return <Navigate to={from} replace />;

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    const base = apiBaseUrl.trim().replace(/\/+$/, "");
    const tid = tenantId.trim();
    const key = apiKey.trim();
    if (!base || !tid || !key) {
      setError("API base URL, tenant ID and API key are all required.");
      return;
    }
    login({ apiBaseUrl: base, tenantId: tid, apiKey: key });
    navigate(from, { replace: true });
  }

  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <form onSubmit={onSubmit} className="card w-full max-w-md space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">kseal console</h1>
          <p className="mt-1 text-sm text-slate-400">
            Sign in with a tenant API key to manage apps, policies and events.
          </p>
        </div>

        <div>
          <label htmlFor="apiBaseUrl" className="label">
            API base URL
          </label>
          <input
            id="apiBaseUrl"
            className="input"
            value={apiBaseUrl}
            onChange={(e) => setApiBaseUrl(e.target.value)}
            placeholder="http://localhost:8080"
            autoComplete="off"
          />
        </div>

        <div>
          <label htmlFor="tenantId" className="label">
            Tenant ID
          </label>
          <input
            id="tenantId"
            className="input"
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            placeholder="tenant uuid"
            autoComplete="off"
          />
        </div>

        <div>
          <label htmlFor="apiKey" className="label">
            API key
          </label>
          <input
            id="apiKey"
            type="password"
            className="input"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="ksk_…"
            autoComplete="off"
          />
        </div>

        {error && (
          <div role="alert" className="text-sm text-rose-300">
            {error}
          </div>
        )}

        <button type="submit" className="btn-primary w-full">
          Sign in
        </button>
      </form>
    </div>
  );
}
