import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../state/useAuth";
import { defaultApiBaseUrl } from "../config";
import { ShieldIcon } from "../components/icons";

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
    <div className="relative flex min-h-full items-center justify-center overflow-hidden p-6">
      {/* Branded gradient backdrop — matches the KChat/docs purple gradient. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 -z-10 bg-gradient-to-br from-[#5161ce] via-[#7b3fe4] to-[#9b59e2]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top_right,rgba(255,255,255,0.18),transparent_40%)]"
      />

      <form onSubmit={onSubmit} className="relative w-full max-w-md space-y-5 rounded-3xl border border-white/20 bg-surface/95 p-7 shadow-2xl shadow-black/20 backdrop-blur">
        <div className="text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-accent to-accent-strong text-white shadow-lg shadow-accent/30">
            <ShieldIcon className="h-6 w-6" />
          </div>
          <h1 className="mt-4 text-2xl font-bold tracking-tight text-fg-strong">
            kseal console
          </h1>
          <p className="mt-1 text-sm leading-relaxed text-fg-muted">
            Sign in to manage your apps, policies, and security events.
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
            placeholder={defaultApiBaseUrl()}
            autoComplete="off"
            aria-describedby="apiBaseUrl-hint"
          />
          <p id="apiBaseUrl-hint" className="mt-1.5 text-xs leading-relaxed text-fg-muted">
            Defaults to this console&rsquo;s origin. In local development
            requests are proxied to the kseal API (set
            {" "}
            <code>KSEAL_DEV_API_PROXY_TARGET</code>, default
            {" "}
            <code>http://localhost:8080</code>); point elsewhere to call a
            remote API directly.
          </p>
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
          <div role="alert" className="rounded-xl bg-rose-500/10 px-3 py-2 text-sm text-rose-600 dark:text-rose-300">
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
