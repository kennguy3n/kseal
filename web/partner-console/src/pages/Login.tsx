import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../state/useAuth";
import { parseTenantIds } from "../api/auth";
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
  const [tenantsText, setTenantsText] = useState(
    session?.tenantIds.join("\n") ?? "",
  );
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);

  if (session) return <Navigate to={from} replace />;

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    const base = apiBaseUrl.trim().replace(/\/+$/, "");
    const tenantIds = parseTenantIds(tenantsText);
    const key = apiKey.trim();
    if (!base || tenantIds.length === 0 || !key) {
      setError(
        "API base URL, at least one tenant ID, and a partner API key are all required.",
      );
      return;
    }
    login({ apiBaseUrl: base, tenantIds, apiKey: key });
    navigate(from, { replace: true });
  }

  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <form onSubmit={onSubmit} className="card w-full max-w-md space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-heading">
            kseal partner console
          </h1>
          <p className="mt-1 text-sm text-muted">
            Sign in with a partner API key to monitor your managed tenant fleet.
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
          <label htmlFor="tenantIds" className="label">
            Tenant IDs (one per line or comma-separated)
          </label>
          <textarea
            id="tenantIds"
            className="input min-h-[96px] font-mono"
            value={tenantsText}
            onChange={(e) => setTenantsText(e.target.value)}
            placeholder={"tenant-a\ntenant-b\ntenant-c"}
            autoComplete="off"
          />
        </div>

        <div>
          <label htmlFor="apiKey" className="label">
            Partner API key
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
          <div role="alert" className="text-sm text-rose-600 dark:text-rose-300">
            {error}
          </div>
        )}

        <button type="submit" className="btn-primary w-full focus-ring">
          Sign in
        </button>
      </form>
    </div>
  );
}
