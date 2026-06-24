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
    <div className="relative flex min-h-full items-center justify-center overflow-hidden p-6">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-br from-[#5161ce] via-[#7b3fe4] to-[#9b59e2]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top_right,rgba(255,255,255,0.18),transparent_40%)]"
      />

      <form onSubmit={onSubmit} className="relative w-full max-w-md space-y-5 rounded-3xl border border-white/20 bg-panel/95 p-7 shadow-2xl shadow-black/20 backdrop-blur">
        <div className="text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-accent to-accent-strong text-accent-fg shadow-lg shadow-accent/30">
            <svg
              className="h-6 w-6"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M12 2 4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5l-8-3z" />
            </svg>
          </div>
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-heading">
            kseal partner console
          </h1>
          <p className="mt-1 text-sm leading-relaxed text-muted">
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
          <div role="alert" className="rounded-xl bg-rose-500/10 px-3 py-2 text-sm text-rose-600 dark:text-rose-300">
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
