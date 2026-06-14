import { useMemo, useState } from "react";
import { useDataProcessingRegistry } from "../hooks/compliance";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  Spinner,
  UnavailableNotice,
} from "../components/ui";
import { AppSelect } from "../components/AppSelect";
import { formatTimestamp } from "../lib/format";
import { isUnavailableError } from "../lib/availability";

// The canonical registry stores a retention window in days (0 means only
// aggregates are kept).
function formatRetention(days: number): string {
  if (days <= 0) return "Aggregates only";
  return `${days} day${days === 1 ? "" : "s"}`;
}

export function DataProcessingPage() {
  const [appId, setAppId] = useState("");
  const registry = useDataProcessingRegistry();

  // The canonical GetDataProcessingRegistry returns the whole tenant registry
  // unpaginated, so the app filter is applied client-side. Selecting an app
  // also keeps tenant-wide (empty app_id) baseline records, since those apply
  // to every app.
  const records = useMemo(() => {
    const all = registry.data ?? [];
    if (!appId) return all;
    return all.filter((r) => r.appId === appId || r.appId === "");
  }, [registry.data, appId]);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-fg-strong">
          Data-processing registry
        </h1>
        <p className="text-sm text-fg-muted">
          What data each app / SDK processes — categories, purpose, retention
          and lawful basis — for your processing register and privacy reviews.
        </p>
      </header>

      <Card title="Scope">
        <AppSelect
          id="dpScope"
          value={appId}
          onChange={setAppId}
          allLabel="All apps + tenant-wide"
        />
      </Card>

      <Card
        title={
          <span>
            Records{" "}
            <span className="text-fg-subtle">({records.length})</span>
          </span>
        }
      >
        {registry.isLoading ? (
          <Spinner />
        ) : registry.isError && isUnavailableError(registry.error) ? (
          <UnavailableNotice feature="The data-processing registry" />
        ) : registry.isError ? (
          <ErrorNotice error={registry.error} />
        ) : records.length === 0 ? (
          <EmptyState>
            No data-processing records declared for this scope.
          </EmptyState>
        ) : (
          <ul className="space-y-3">
            {records.map((r, i) => (
              <li
                key={`${r.appId}|${i}`}
                className="rounded-lg border border-line p-4"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-fg-strong">
                    {r.dataCategories.join(", ") || "Data processing"}
                  </span>
                  {r.thirdPartySharing ? (
                    <Badge tone="bg-amber-500/10 text-amber-700 border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-300">
                      Shared with third party
                    </Badge>
                  ) : (
                    <Badge tone="bg-emerald-500/10 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-300">
                      Not shared
                    </Badge>
                  )}
                  <span className="text-xs text-fg-subtle">
                    {r.appId ? `app ${r.appId}` : "tenant-wide"}
                  </span>
                </div>
                <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="label">Purpose</dt>
                    <dd className="text-fg">{r.purpose || "—"}</dd>
                  </div>
                  <div>
                    <dt className="label">Retention</dt>
                    <dd className="text-fg">
                      {formatRetention(r.retentionDays)}
                    </dd>
                  </div>
                  <div>
                    <dt className="label">Lawful basis</dt>
                    <dd className="text-fg">{r.legalBasis || "—"}</dd>
                  </div>
                  <div>
                    <dt className="label">Updated</dt>
                    <dd className="font-mono text-xs text-fg-muted">
                      {formatTimestamp(r.updatedAt)}
                    </dd>
                  </div>
                </dl>
                {r.dataCategories.length > 0 && (
                  <div className="mt-3">
                    <div className="label">Categories</div>
                    <div className="flex flex-wrap gap-1.5">
                      {r.dataCategories.map((f) => (
                        <span
                          key={f}
                          className="rounded-md border border-line-strong px-2 py-0.5 font-mono text-xs text-fg-muted"
                        >
                          {f}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
