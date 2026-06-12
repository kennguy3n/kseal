import type { ReactNode } from "react";
import { ConnectError } from "@connectrpc/connect";

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

// Keyset-pagination control for the list views. Renders nothing when the server
// reported no further pages (empty next_page_token), so callers can drop it in
// unconditionally below a list.
export function LoadMore({
  hasNextPage,
  isFetchingNextPage,
  onClick,
}: {
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  onClick: () => void;
}) {
  if (!hasNextPage) return null;
  return (
    <div className="mt-4 flex justify-center">
      <button
        type="button"
        className="btn-ghost"
        onClick={onClick}
        disabled={isFetchingNextPage}
      >
        {isFetchingNextPage ? "Loading…" : "Load more"}
      </button>
    </div>
  );
}

// Renders a Connect error as a thin, defensive fallback for transient failures
// (the read RPCs are implemented server-side, so this is no longer a "pending
// support" degrade path).
export function ErrorNotice({ error }: { error: unknown }) {
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
