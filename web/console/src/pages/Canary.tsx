import { useState } from "react";
import { useCanaryRollouts } from "../hooks/compliance";
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
import {
  canaryHealthLabels,
  canaryHealthTone,
  formatRate,
  formatTimestamp,
} from "../lib/format";
import { isUnavailableError } from "../lib/availability";

// A thin progress bar visualizing the staged-rollout percentage.
function RolloutBar({ percentage }: { percentage: number }) {
  const pct = Math.max(0, Math.min(100, percentage));
  return (
    <div
      className="h-2 w-full overflow-hidden rounded-full bg-slate-800"
      role="progressbar"
      aria-valuenow={pct}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="h-full rounded-full bg-indigo-500"
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

export function CanaryPage() {
  const [appId, setAppId] = useState("");
  const canary = useCanaryRollouts(appId);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-50">Canary monitor</h1>
        <p className="text-sm text-slate-400">
          Staged policy/config rollouts: rollout percentage, cohort health and
          auto-rollback status.
        </p>
      </header>

      <Card title="Scope">
        <AppSelect id="canaryScope" value={appId} onChange={setAppId} />
      </Card>

      <Card
        title={
          <span>
            Rollouts{" "}
            <span className="text-slate-500">({canary.data?.length ?? 0})</span>
          </span>
        }
      >
        {canary.isLoading ? (
          <Spinner />
        ) : canary.isError && isUnavailableError(canary.error) ? (
          <UnavailableNotice feature="The canary monitor" />
        ) : canary.isError ? (
          <ErrorNotice error={canary.error} />
        ) : !canary.data || canary.data.length === 0 ? (
          <EmptyState>No staged rollouts for this scope.</EmptyState>
        ) : (
          <>
            <ul className="space-y-3">
              {canary.data.map((r) => {
                const m = r.metrics;
                const errorRate = m?.errorRate ?? 0;
                const baseline = m?.baselineErrorRate ?? 0;
                const regressed = errorRate > baseline;
                return (
                  <li
                    key={r.id}
                    className="rounded-lg border border-slate-800 p-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-slate-100">
                          {r.policyName || r.policyId || "rollout"}
                        </span>
                        <Badge tone={canaryHealthTone(r.health)}>
                          {canaryHealthLabels[r.health]}
                        </Badge>
                        {r.rolledBack && (
                          <Badge tone="bg-rose-500/15 text-rose-300 border-rose-500/30">
                            Auto-rolled back
                          </Badge>
                        )}
                        {!r.rolledBack && r.autoRollbackArmed && (
                          <Badge tone="bg-sky-500/15 text-sky-300 border-sky-500/30">
                            Auto-rollback armed
                          </Badge>
                        )}
                      </div>
                      <span className="text-sm font-semibold text-slate-200">
                        {r.percentage}%
                      </span>
                    </div>

                    <div className="mt-3">
                      <RolloutBar percentage={r.percentage} />
                    </div>

                    <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
                      <div>
                        <dt className="label">Canary error rate</dt>
                        <dd
                          className={
                            regressed ? "text-amber-300" : "text-slate-300"
                          }
                        >
                          {formatRate(errorRate)}
                        </dd>
                      </div>
                      <div>
                        <dt className="label">Baseline</dt>
                        <dd className="text-slate-300">
                          {formatRate(baseline)}
                        </dd>
                      </div>
                      <div>
                        <dt className="label">Cohort</dt>
                        <dd className="text-slate-300">
                          {(m?.cohortInstances ?? 0n).toString()} instances ·{" "}
                          {(m?.sampleEvents ?? 0n).toString()} events
                        </dd>
                      </div>
                      <div>
                        <dt className="label">Updated</dt>
                        <dd className="font-mono text-xs text-slate-400">
                          {formatTimestamp(r.updatedAt)}
                        </dd>
                      </div>
                    </dl>

                    {r.rolledBack && r.rollbackReason && (
                      <p className="mt-3 text-xs text-rose-300/80">
                        Rollback reason: {r.rollbackReason}
                      </p>
                    )}
                  </li>
                );
              })}
            </ul>
            <LoadMore
              hasNextPage={canary.hasNextPage}
              isFetchingNextPage={canary.isFetchingNextPage}
              onClick={() => void canary.fetchNextPage()}
            />
          </>
        )}
      </Card>
    </div>
  );
}
