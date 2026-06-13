import { useState } from "react";
import { useCanaryStatus } from "../hooks/compliance";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  Spinner,
  UnavailableNotice,
} from "../components/ui";
import { AppSelect } from "../components/AppSelect";
import { CanaryState } from "../gen/kseal/v1/compliance_pb";
import {
  canaryStateLabels,
  canaryStateTone,
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
  const canary = useCanaryStatus(appId);
  const status = canary.data ?? null;

  // The candidate cohort regresses when its observed block rate crosses the
  // configured auto-rollback threshold.
  const regressed =
    status !== null &&
    status.rollbackThreshold > 0 &&
    status.blockRate > status.rollbackThreshold;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-50">Canary monitor</h1>
        <p className="text-sm text-slate-400">
          Staged policy/config rollout for an app: rollout percentage, candidate
          health and auto-rollback status.
        </p>
      </header>

      <Card title="Scope">
        <AppSelect id="canaryScope" value={appId} onChange={setAppId} />
      </Card>

      <Card title="Rollout">
        {canary.isLoading ? (
          <Spinner />
        ) : canary.isError && isUnavailableError(canary.error) ? (
          <UnavailableNotice feature="The canary monitor" />
        ) : canary.isError ? (
          <ErrorNotice error={canary.error} />
        ) : status === null ? (
          <EmptyState>No staged rollout for this scope.</EmptyState>
        ) : (
          <div className="rounded-lg border border-slate-800 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-slate-100">
                  {status.candidatePolicyId || "candidate"}
                </span>
                <Badge tone={canaryStateTone(status.state)}>
                  {canaryStateLabels[status.state]}
                </Badge>
                {status.state === CanaryState.ACTIVE && (
                  <Badge tone="bg-sky-500/15 text-sky-300 border-sky-500/30">
                    Auto-rollback armed
                  </Badge>
                )}
              </div>
              <span className="text-sm font-semibold text-slate-200">
                {status.percent}%
              </span>
            </div>

            <div className="mt-3">
              <RolloutBar percentage={status.percent} />
            </div>

            <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="label">Candidate block rate</dt>
                <dd className={regressed ? "text-amber-300" : "text-slate-300"}>
                  {formatRate(status.blockRate)}
                </dd>
              </div>
              <div>
                <dt className="label">Rollback threshold</dt>
                <dd className="text-slate-300">
                  {formatRate(status.rollbackThreshold)}
                </dd>
              </div>
              <div>
                <dt className="label">Sample</dt>
                <dd className="text-slate-300">
                  {status.sampleCount.toString()} decisions
                </dd>
              </div>
              <div>
                <dt className="label">Updated</dt>
                <dd className="font-mono text-xs text-slate-400">
                  {formatTimestamp(status.updatedAt)}
                </dd>
              </div>
            </dl>

            <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
              <div>
                <dt className="label">Stable (last-known-good)</dt>
                <dd className="font-mono text-xs text-slate-400">
                  {status.stablePolicyId || "—"}
                </dd>
              </div>
            </dl>

            {status.lastEvent && (
              <p
                className={
                  status.state === CanaryState.ROLLED_BACK
                    ? "mt-3 text-xs text-rose-300/80"
                    : "mt-3 text-xs text-slate-400"
                }
              >
                {status.lastEvent}
              </p>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
