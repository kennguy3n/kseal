import { useMemo, useState } from "react";
import { useAuditEvents, useVerifyAuditChain } from "../hooks/compliance";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  InfoHint,
  LoadMore,
  SkeletonRows,
  UnavailableNotice,
} from "../components/ui";
import {
  AlertIcon,
  InfoIcon,
  RefreshIcon,
  ShieldIcon,
} from "../components/icons";
import { formatTimestamp } from "../lib/format";
import { isUnavailableError } from "../lib/availability";
import { docs } from "../lib/links";

// Renders the result of the dedicated VerifyAuditChain RPC across all of its
// distinct outcomes. Crucially it distinguishes "verification unavailable on
// this deployment" (the RPC is not implemented/reachable) from "verified" and
// "broken", so an operator is never left guessing why no chain status shows.
// Only the tamper case uses role="alert"; every other state is role="status".
function ChainStatusBanner({
  chain,
}: {
  chain: ReturnType<typeof useVerifyAuditChain>;
}) {
  if (chain.isLoading) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="flex items-center gap-2 rounded-lg border border-line bg-surface px-4 py-3 text-sm text-fg-muted"
      >
        <span className="h-3 w-3 animate-spin rounded-full border-2 border-line-strong border-t-accent-strong" />
        Verifying audit chain integrity…
      </div>
    );
  }

  if (chain.isError) {
    // UNIMPLEMENTED/UNAVAILABLE => the capability isn't on this deployment.
    if (isUnavailableError(chain.error)) {
      return (
        <div
          role="status"
          className="flex items-start gap-3 rounded-lg border border-dashed border-line-strong bg-elevated/50 p-4 text-sm"
        >
          <InfoIcon className="mt-0.5 h-5 w-5 shrink-0 text-fg-muted" />
          <div>
            <div className="font-medium text-fg-strong">
              Chain verification not available on this deployment
            </div>
            <p className="mt-1 text-fg-muted">
              Entries below are still recorded and hash-chained. This server
              build does not expose the cryptographic{" "}
              <span className="font-mono">VerifyAuditChain</span> check, so
              end-to-end integrity can be confirmed once it is enabled.
            </p>
          </div>
        </div>
      );
    }
    // A real failure to run the check (e.g. transient network) — offer a retry
    // rather than implying tamper.
    return (
      <div
        role="status"
        className="flex items-start gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-700 dark:text-amber-200"
      >
        <AlertIcon className="mt-0.5 h-5 w-5 shrink-0" />
        <div className="flex-1">
          <div className="font-medium">Couldn’t verify the audit chain</div>
          <p className="mt-0.5 text-amber-700/90 dark:text-amber-200/80">
            The integrity check could not be run just now. This does not mean
            tampering — try again.
          </p>
          <button
            type="button"
            onClick={() => void chain.refetch()}
            className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-amber-500/40 px-2.5 py-1 text-xs font-medium"
          >
            <RefreshIcon className="h-3.5 w-3.5" />
            Re-run verification
          </button>
        </div>
      </div>
    );
  }

  const data = chain.data;
  if (!data) return null;

  if (!data.intact) {
    return (
      <div
        role="alert"
        className="flex items-start gap-3 rounded-lg border border-rose-500/50 bg-rose-500/10 p-4 text-sm text-rose-700 dark:bg-rose-900/20 dark:text-rose-200"
      >
        <AlertIcon className="mt-0.5 h-5 w-5 shrink-0" />
        <div>
          <div className="font-medium">Audit chain verification failed</div>
          <p className="mt-0.5 text-rose-700/90 dark:text-rose-200/80">
            {data.brokenSeq > 0n
              ? `A break was detected at sequence ${data.brokenSeq.toString()}. `
              : ""}
            Entries may have been tampered with. Treat this trail as untrusted
            and investigate immediately.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div
      role="status"
      className="flex items-start gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-700 dark:text-emerald-300"
    >
      <ShieldIcon className="mt-0.5 h-5 w-5 shrink-0" />
      <div>
        <div className="font-medium">Audit chain verified</div>
        <p className="mt-0.5 text-emerald-700/90 dark:text-emerald-300/80">
          {data.verifiedCount > 0n
            ? `${data.verifiedCount.toString()} entries are cryptographically linked with no gaps or edits.`
            : "The hash chain is intact."}
        </p>
      </div>
    </div>
  );
}

function toMillis(local: string): number | undefined {
  if (!local) return undefined;
  const ms = new Date(local).getTime();
  return Number.isNaN(ms) ? undefined : ms;
}

// Compact, deterministic rendering of the small non-PII metadata map.
function formatMetadata(metadata: Record<string, string>): string {
  const keys = Object.keys(metadata).sort();
  if (keys.length === 0) return "—";
  return keys.map((k) => `${k}=${metadata[k]}`).join(", ");
}

export function AuditTrailPage() {
  const [actionInput, setActionInput] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [startLocal, setStartLocal] = useState("");
  const [endLocal, setEndLocal] = useState("");

  // Debounce the free-text filters so typing coalesces into a single query
  // instead of firing a request per keystroke. Date pickers change discretely,
  // so they drive the query directly.
  const actionQuery = useDebouncedValue(actionInput);
  const resourceQuery = useDebouncedValue(resourceType);

  const audit = useAuditEvents({
    action: actionQuery.trim() || undefined,
    resourceType: resourceQuery.trim() || undefined,
    startTime: toMillis(startLocal),
    endTime: toMillis(endLocal),
  });
  const chain = useVerifyAuditChain();

  const events = useMemo(
    () => audit.data?.pages.flatMap((p) => p.events) ?? [],
    [audit.data],
  );

  const hasFilters =
    Boolean(actionInput) ||
    Boolean(resourceType) ||
    Boolean(startLocal) ||
    Boolean(endLocal);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <h1 className="text-xl font-semibold text-fg-strong">
              Audit trail
            </h1>
            <InfoHint label="About the audit trail">
              Every control-plane mutation is appended to a tenant-scoped,
              hash-chained log. Each entry references the previous entry’s hash,
              so any insertion, deletion or edit breaks the chain and is
              detectable.
            </InfoHint>
          </div>
          <p className="mt-1 max-w-2xl text-sm text-fg-muted">
            Tamper-evident log of control-plane mutations including kill-switch
            and canary actions. Newest first.{" "}
            <a
              href={docs.auditTrail()}
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              Learn how chaining works
            </a>
            .
          </p>
        </div>
      </header>

      <Card title="Filters">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <label htmlFor="auditAction" className="label">
              Action
            </label>
            <input
              id="auditAction"
              className="input"
              placeholder="e.g. policy.activate"
              value={actionInput}
              onChange={(e) => setActionInput(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="auditResource" className="label">
              Resource type
            </label>
            <input
              id="auditResource"
              className="input"
              placeholder="policy, kill_switch, app…"
              value={resourceType}
              onChange={(e) => setResourceType(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="auditStart" className="label">
              From
            </label>
            <input
              id="auditStart"
              type="datetime-local"
              className="input"
              value={startLocal}
              onChange={(e) => setStartLocal(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="auditEnd" className="label">
              To
            </label>
            <input
              id="auditEnd"
              type="datetime-local"
              className="input"
              value={endLocal}
              onChange={(e) => setEndLocal(e.target.value)}
            />
          </div>
        </div>
        {hasFilters && (
          <button
            type="button"
            className="btn-ghost mt-4"
            onClick={() => {
              setActionInput("");
              setResourceType("");
              setStartLocal("");
              setEndLocal("");
            }}
          >
            Clear filters
          </button>
        )}
      </Card>

      <ChainStatusBanner chain={chain} />

      <Card
        title={
          <span>
            Entries <span className="text-fg-subtle">({events.length})</span>
          </span>
        }
      >
        {audit.isLoading ? (
          <SkeletonRows rows={5} />
        ) : audit.isError && isUnavailableError(audit.error) ? (
          <UnavailableNotice feature="The audit trail" />
        ) : audit.isError ? (
          <ErrorNotice
            error={audit.error}
            onRetry={() => void audit.refetch()}
          />
        ) : events.length === 0 ? (
          <EmptyState>No audit entries match the current filters.</EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-line">
                    <th className="th">Seq</th>
                    <th className="th">Time</th>
                    <th className="th">Actor</th>
                    <th className="th">Action</th>
                    <th className="th">Resource</th>
                    <th className="th">Context</th>
                    <th className="th">Chain</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr
                      key={e.seq.toString()}
                      className="border-b border-line/60"
                    >
                      <td className="td font-mono text-xs text-fg-subtle">
                        {e.seq.toString()}
                      </td>
                      <td className="td font-mono text-xs text-fg-muted">
                        {formatTimestamp(e.createdAt)}
                      </td>
                      <td className="td text-fg">
                        {e.actorKeyId || "—"}
                      </td>
                      <td className="td">
                        <Badge>{e.action || "—"}</Badge>
                      </td>
                      <td className="td text-fg">
                        {e.resourceType}
                        {e.resourceId ? (
                          <span className="font-mono text-xs text-fg-subtle">
                            {" "}
                            {e.resourceId}
                          </span>
                        ) : null}
                      </td>
                      <td className="td text-xs text-fg-muted">
                        {formatMetadata(e.metadata)}
                      </td>
                      <td
                        className="td font-mono text-xs text-fg-subtle"
                        title={e.hash}
                      >
                        {e.hash ? `${e.hash.slice(0, 12)}…` : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <LoadMore
              hasNextPage={audit.hasNextPage}
              isFetchingNextPage={audit.isFetchingNextPage}
              onClick={() => void audit.fetchNextPage()}
            />
          </>
        )}
      </Card>
    </div>
  );
}
