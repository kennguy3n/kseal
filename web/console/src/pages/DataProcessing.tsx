import { useState } from "react";
import { useDataProcessingRecords } from "../hooks/compliance";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  LoadMore,
  Spinner,
  UnavailableNotice,
} from "../components/ui";
import { AppSelect } from "../components/AppSelect";
import { formatTimestamp } from "../lib/format";
import { isUnavailableError } from "../lib/availability";

export function DataProcessingPage() {
  const [appId, setAppId] = useState("");
  const records = useDataProcessingRecords(appId);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-50">
          Data-processing registry
        </h1>
        <p className="text-sm text-slate-400">
          What data each app / SDK processes — category, purpose, retention and
          lawful basis — for your processing register and privacy reviews.
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
            <span className="text-slate-500">
              ({records.data?.length ?? 0})
            </span>
          </span>
        }
      >
        {records.isLoading ? (
          <Spinner />
        ) : records.isError && isUnavailableError(records.error) ? (
          <UnavailableNotice feature="The data-processing registry" />
        ) : records.isError ? (
          <ErrorNotice error={records.error} />
        ) : !records.data || records.data.length === 0 ? (
          <EmptyState>
            No data-processing records declared for this scope.
          </EmptyState>
        ) : (
          <>
            <ul className="space-y-3">
              {records.data.map((r) => (
                <li
                  key={r.id}
                  className="rounded-lg border border-slate-800 p-4"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-slate-100">
                      {r.category}
                    </span>
                    {r.personalData ? (
                      <Badge tone="bg-amber-500/15 text-amber-300 border-amber-500/30">
                        Personal data
                      </Badge>
                    ) : (
                      <Badge tone="bg-emerald-500/15 text-emerald-300 border-emerald-500/30">
                        Non-personal
                      </Badge>
                    )}
                    <span className="text-xs text-slate-500">
                      {r.appId ? `app ${r.appId}` : "tenant-wide"}
                    </span>
                  </div>
                  <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
                    <div>
                      <dt className="label">Purpose</dt>
                      <dd className="text-slate-300">{r.purpose || "—"}</dd>
                    </div>
                    <div>
                      <dt className="label">Retention</dt>
                      <dd className="text-slate-300">{r.retention || "—"}</dd>
                    </div>
                    <div>
                      <dt className="label">Lawful basis</dt>
                      <dd className="text-slate-300">{r.legalBasis || "—"}</dd>
                    </div>
                    <div>
                      <dt className="label">Updated</dt>
                      <dd className="font-mono text-xs text-slate-400">
                        {formatTimestamp(r.updatedAt)}
                      </dd>
                    </div>
                  </dl>
                  {r.dataFields.length > 0 && (
                    <div className="mt-3">
                      <div className="label">Fields</div>
                      <div className="flex flex-wrap gap-1.5">
                        {r.dataFields.map((f) => (
                          <span
                            key={f}
                            className="rounded-md border border-slate-700 px-2 py-0.5 font-mono text-xs text-slate-400"
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
            <LoadMore
              hasNextPage={records.hasNextPage}
              isFetchingNextPage={records.isFetchingNextPage}
              onClick={() => void records.fetchNextPage()}
            />
          </>
        )}
      </Card>
    </div>
  );
}
