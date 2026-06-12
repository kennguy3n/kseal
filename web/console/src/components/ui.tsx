import type { ReactNode } from "react";
import { ConnectError, Code } from "@connectrpc/connect";

export function Card({
  title,
  actions,
  children,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="mb-4 flex items-center justify-between">
          {title && (
            <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
          )}
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="card">
      <div className="text-xs uppercase tracking-wide text-slate-400">
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold text-slate-50">{value}</div>
    </div>
  );
}

export function Badge({
  children,
  tone = "bg-slate-500/15 text-slate-300 border-slate-500/30",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center gap-2 text-sm text-slate-400"
    >
      <span className="h-3 w-3 animate-spin rounded-full border-2 border-slate-600 border-t-indigo-400" />
      {label}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-700 p-6 text-center text-sm text-slate-400">
      {children}
    </div>
  );
}

// Renders a Connect error. Unimplemented is surfaced as an informative notice
// because the read API (QueryService) is pending server support.
export function ErrorNotice({ error }: { error: unknown }) {
  if (error instanceof ConnectError && error.code === Code.Unimplemented) {
    return (
      <div className="rounded-lg border border-amber-700/50 bg-amber-900/20 p-4 text-sm text-amber-200">
        This view depends on the server read API (<code>QueryService</code>),
        which this server build does not implement yet. The console is wired and
        will populate once the data plane ships it.
      </div>
    );
  }
  const message =
    error instanceof ConnectError
      ? error.rawMessage
      : error instanceof Error
        ? error.message
        : String(error);
  return (
    <div
      role="alert"
      className="rounded-lg border border-rose-700/50 bg-rose-900/20 p-4 text-sm text-rose-200"
    >
      {message}
    </div>
  );
}
