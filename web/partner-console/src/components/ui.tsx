import type { ReactNode } from "react";
import { ConnectError } from "@connectrpc/connect";

export function Card({
  title,
  description,
  actions,
  children,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="card">
      {(title || actions || description) && (
        <header className="mb-5 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title && (
              <h2 className="text-base font-semibold text-heading">{title}</h2>
            )}
            {description && (
              <p className="mt-1 text-sm text-muted">{description}</p>
            )}
          </div>
          {actions && <div className="shrink-0">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="card">
      <div className="text-xs font-semibold uppercase tracking-wider text-muted">{label}</div>
      <div className="mt-2 text-3xl font-bold tracking-tight text-heading tabular-nums">
        {value}
      </div>
    </div>
  );
}

export function Badge({
  children,
  tone = "bg-slate-500/15 text-slate-600 dark:text-slate-300 border-slate-500/30",
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
      className="flex items-center gap-2 text-sm text-muted"
    >
      <span className="h-3 w-3 animate-spin rounded-full border-2 border-line-strong border-t-accent" />
      {label}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-2xl border border-dashed border-line-strong bg-raised/40 p-8 text-center text-sm text-muted">
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
      className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-700 dark:border-rose-700/50 dark:bg-rose-900/20 dark:text-rose-200"
    >
      {message}
    </div>
  );
}
