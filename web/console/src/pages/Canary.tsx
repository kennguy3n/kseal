import { useState } from "react";
import { useCanaryStatus } from "../hooks/compliance";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  InfoHint,
  SkeletonRows,
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
      className="h-2 w-full overflow-hidden rounded-full bg-elevated"
      role="progressbar"
      aria-valuenow={pct}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="h-full rounded-full bg-accent-strong"
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
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <h1 className="text-xl font-semibold text-fg-strong">
              Canary monitor
            </h1>
            <InfoHint label="About canary rollouts">
              A canary rolls a new policy or config out to a small percentage of
              traffic first. kseal watches the candidate cohort’s block rate and
              automatically rolls back to the last-known-good policy if it
              crosses the configured threshold — so a bad change can’t take down
              every user.
            </InfoHint>
          </div>
          <p className="mt-1 max-w-2xl text-sm text-fg-muted">
            Staged policy/config rollout for an app: rollout percentage,
            candidate health and auto-rollback status.
          </p>
        </div>
      </header>

      <Card title="Scope">
        <AppSelect id="canaryScope" value={appId} onChange={setAppId} />
      </Card>

      <Card title="Rollout">
        {canary.isLoading ? (
          <SkeletonRows rows={2} />
        ) : canary.isError && isUnavailableError(canary.error) ? (
          <UnavailableNotice feature="The canary monitor" />
        ) : canary.isError ? (
          <ErrorNotice
            error={canary.error}
            onRetry={() => void canary.refetch()}
          />
        ) : status === null ? (
          <EmptyState>No staged rollout for this scope.</EmptyState>
        ) : (
          <div className="rounded-lg border border-line p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-fg-strong">
                  {status.candidatePolicyId || "candidate"}
                </span>
                <Badge tone={canaryStateTone(status.state)}>
                  {canaryStateLabels[status.state]}
                </Badge>
                {status.state === CanaryState.ACTIVE && (
                  <Badge tone="bg-sky-500/10 text-sky-700 border-sky-500/30 dark:bg-sky-500/15 dark:text-sky-300">
                    Auto-rollback armed
                  </Badge>
                )}
              </div>
              <span className="text-sm font-semibold text-fg">
                {status.percent}%
              </span>
            </div>

            <div className="mt-3">
              <RolloutBar percentage={status.percent} />
            </div>

            <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="label">Candidate block rate</dt>
                <dd className={regressed ? "text-amber-600 dark:text-amber-300" : "text-fg"}>
                  {formatRate(status.blockRate)}
                </dd>
              </div>
              <div>
                <dt className="label">Rollback threshold</dt>
                <dd className="text-fg">
                  {formatRate(status.rollbackThreshold)}
                </dd>
              </div>
              <div>
                <dt className="label">Sample</dt>
                <dd className="text-fg">
                  {status.sampleCount.toString()} decisions
                </dd>
              </div>
              <div>
                <dt className="label">Updated</dt>
                <dd className="font-mono text-xs text-fg-muted">
                  {formatTimestamp(status.updatedAt)}
                </dd>
              </div>
            </dl>

            <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
              <div>
                <dt className="label">Stable (last-known-good)</dt>
                <dd className="font-mono text-xs text-fg-muted">
                  {status.stablePolicyId || "—"}
                </dd>
              </div>
            </dl>

            {status.lastEvent && (
              <p
                className={
                  status.state === CanaryState.ROLLED_BACK
                    ? "mt-3 text-xs text-rose-600/90 dark:text-rose-300/80"
                    : "mt-3 text-xs text-fg-muted"
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
