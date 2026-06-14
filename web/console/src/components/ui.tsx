import {
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  AlertIcon,
  InboxIcon,
  InfoIcon,
  RefreshIcon,
} from "./icons";
import { errorMessage } from "../lib/errors";

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
        <header className="mb-4 flex items-start justify-between gap-3">
          <div className="min-w-0">
            {title && (
              <h2 className="text-sm font-semibold text-fg-strong">{title}</h2>
            )}
            {description && (
              <p className="mt-0.5 text-xs text-fg-muted">{description}</p>
            )}
          </div>
          {actions && <div className="shrink-0">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

// Standardized page title + lead-in used across every view so headings, spacing
// and the optional right-aligned actions are consistent.
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold text-fg-strong">{title}</h1>
        {description && (
          <p className="mt-1 max-w-2xl text-sm text-fg-muted">{description}</p>
        )}
      </div>
      {actions && <div className="shrink-0">{actions}</div>}
    </header>
  );
}

export function Stat({
  label,
  value,
  hint,
  loading = false,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  // When the value's own query is still loading, show a placeholder for this
  // card instead of a stale dash — each stat tracks its own source query.
  loading?: boolean;
}) {
  if (loading) return <SkeletonStat />;
  return (
    <div className="card">
      <div className="flex items-center gap-1.5 text-xs uppercase tracking-wide text-fg-muted">
        {label}
        {hint && <InfoHint label={`About ${label}`}>{hint}</InfoHint>}
      </div>
      <div className="mt-2 text-2xl font-semibold text-fg-strong">{value}</div>
    </div>
  );
}

export function Badge({
  children,
  tone = "bg-fg-subtle/15 text-fg border-line-strong",
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
      className="flex items-center gap-2 text-sm text-fg-muted"
    >
      <span className="h-3 w-3 animate-spin rounded-full border-2 border-line-strong border-t-accent-strong" />
      {label}
    </div>
  );
}

// A single shimmer placeholder block. Width/height are controlled by the
// caller via className (e.g. `h-4 w-32`).
export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} aria-hidden="true" />;
}

// A labelled set of skeleton rows used as the loading state for a panel. The
// surrounding status role announces "Loading" to assistive tech while the
// visual placeholders render.
export function SkeletonRows({
  rows = 3,
  label = "Loading…",
}: {
  rows?: number;
  label?: string;
}) {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">{label}</span>
      <div className="space-y-3">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center gap-3">
            <Skeleton className="h-9 w-9 shrink-0 rounded-full" />
            <div className="flex-1 space-y-2">
              <Skeleton className="h-3 w-1/3" />
              <Skeleton className="h-3 w-2/3" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Skeleton sized for the metric cards on the dashboard.
export function SkeletonStat() {
  return (
    <div className="card" aria-hidden="true">
      <Skeleton className="h-3 w-16" />
      <Skeleton className="mt-3 h-7 w-12" />
    </div>
  );
}

export function EmptyState({
  title,
  icon = <InboxIcon className="h-5 w-5" />,
  action,
  children,
}: {
  title?: ReactNode;
  icon?: ReactNode;
  action?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-line-strong p-6 text-center">
      <span className="text-fg-subtle" aria-hidden="true">
        {icon}
      </span>
      {title && (
        <div className="text-sm font-medium text-fg-strong">{title}</div>
      )}
      {children && <div className="text-sm text-fg-muted">{children}</div>}
      {action && <div className="mt-1">{action}</div>}
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

// Graceful-degradation state for a ComplianceService RPC that the connected
// server build does not expose yet (returns UNIMPLEMENTED/UNAVAILABLE). Distinct
// from ErrorNotice: this is an expected, non-alarming "not available on this
// deployment" state, so it uses role="status" rather than role="alert".
export function UnavailableNotice({
  feature,
  children,
}: {
  feature: string;
  children?: ReactNode;
}) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-start gap-3 rounded-lg border border-dashed border-amber-500/40 bg-amber-500/10 p-5 text-sm text-amber-700 dark:text-amber-200/90"
    >
      <InfoIcon className="mt-0.5 h-5 w-5 shrink-0" />
      <div>
        <div className="font-medium text-amber-800 dark:text-amber-100">
          {feature} is not available yet
        </div>
        <p className="mt-1 text-amber-700/90 dark:text-amber-200/70">
          {children ??
            "This view depends on a control-plane capability that has not been deployed to your environment yet. It will populate automatically once available."}
        </p>
      </div>
    </div>
  );
}

// Renders a Connect error as a thin, defensive fallback for transient failures
// (the read RPCs are implemented server-side, so this is no longer a "pending
// support" degrade path). An optional `onRetry` adds a retry affordance.
export function ErrorNotice({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-lg border border-rose-500/50 bg-rose-500/10 p-4 text-sm text-rose-700 dark:bg-rose-900/20 dark:text-rose-200"
    >
      <AlertIcon className="mt-0.5 h-5 w-5 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="font-medium">Something went wrong</div>
        <p className="mt-0.5 break-words text-rose-700/90 dark:text-rose-200/80">
          {errorMessage(error)}
        </p>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-rose-500/40 px-2.5 py-1 text-xs font-medium text-rose-700 hover:bg-rose-500/10 dark:text-rose-200"
          >
            <RefreshIcon className="h-3.5 w-3.5" />
            Try again
          </button>
        )}
      </div>
    </div>
  );
}

// Accessible inline explanation: a small info button that toggles a popover
// describing the adjacent control. Keyboard operable (Enter/Space toggle,
// Escape closes) and announced via aria-expanded + aria-controls.
export function InfoHint({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const ref = useRef<HTMLSpanElement>(null);

  return (
    <span
      ref={ref}
      className="relative inline-flex"
      onBlur={(e) => {
        if (!ref.current?.contains(e.relatedTarget as Node)) setOpen(false);
      }}
    >
      <button
        type="button"
        aria-label={label}
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => {
          if (e.key === "Escape") setOpen(false);
        }}
        className="inline-flex h-4 w-4 items-center justify-center rounded-full text-fg-subtle hover:text-fg"
      >
        <InfoIcon className="h-3.5 w-3.5" />
      </button>
      {open && (
        <span
          id={panelId}
          role="note"
          className="absolute left-1/2 top-6 z-20 w-64 -translate-x-1/2 rounded-lg border border-line bg-surface p-3 text-left text-xs font-normal normal-case tracking-normal text-fg shadow-lg"
        >
          {children}
        </span>
      )}
    </span>
  );
}
