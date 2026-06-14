import { useMemo, useState } from "react";
import { useAuditEvents, useVerifyAuditChain } from "../hooks/compliance";
import { useDebouncedValue } from "../hooks/useDebouncedValue";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  LoadMore,
  Spinner,
  UnavailableNotice,
} from "../components/ui";
import { formatTimestamp } from "../lib/format";
import { isUnavailableError } from "../lib/availability";

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
  // The dedicated VerifyAuditChain RPC recomputes the whole tenant chain; warn
  // if it is not intact (an insertion, deletion, or edit was detected).
  const chainBroken = chain.data && !chain.data.intact ? chain.data : null;

  const hasFilters =
    Boolean(actionInput) ||
    Boolean(resourceType) ||
    Boolean(startLocal) ||
    Boolean(endLocal);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-50">Audit trail</h1>
        <p className="text-sm text-slate-400">
          Tenant-scoped, hash-chained log of control-plane mutations including
          kill-switch and canary actions. Newest first.
        </p>
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

      {chainBroken && (
        <div
          role="alert"
          className="rounded-lg border border-rose-700/50 bg-rose-900/20 p-4 text-sm text-rose-200"
        >
          Audit chain verification failed
          {chainBroken.brokenSeq > 0n
            ? ` at sequence ${chainBroken.brokenSeq.toString()}`
            : ""}
          . Entries may have been tampered with.
        </div>
      )}

      <Card
        title={
          <span>
            Entries <span className="text-slate-500">({events.length})</span>
          </span>
        }
      >
        {audit.isLoading ? (
          <Spinner />
        ) : audit.isError && isUnavailableError(audit.error) ? (
          <UnavailableNotice feature="The audit trail" />
        ) : audit.isError ? (
          <ErrorNotice error={audit.error} />
        ) : events.length === 0 ? (
          <EmptyState>No audit entries match the current filters.</EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-800">
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
                      className="border-b border-slate-800/60"
                    >
                      <td className="td font-mono text-xs text-slate-500">
                        {e.seq.toString()}
                      </td>
                      <td className="td font-mono text-xs text-slate-400">
                        {formatTimestamp(e.createdAt)}
                      </td>
                      <td className="td text-slate-300">
                        {e.actorKeyId || "—"}
                      </td>
                      <td className="td">
                        <Badge>{e.action || "—"}</Badge>
                      </td>
                      <td className="td text-slate-300">
                        {e.resourceType}
                        {e.resourceId ? (
                          <span className="font-mono text-xs text-slate-500">
                            {" "}
                            {e.resourceId}
                          </span>
                        ) : null}
                      </td>
                      <td className="td text-xs text-slate-400">
                        {formatMetadata(e.metadata)}
                      </td>
                      <td
                        className="td font-mono text-xs text-slate-500"
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
