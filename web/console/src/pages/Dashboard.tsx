import { useMemo } from "react";
import { Link } from "react-router-dom";
import {
  useTenantOverview,
  useTrustSessionStats,
} from "../hooks/queries";
import {
  Card,
  ErrorNotice,
  Stat,
  Badge,
  EmptyState,
  PageHeader,
  SkeletonRows,
} from "../components/ui";
import { Onboarding } from "../components/Onboarding";
import {
  eventTypeLabels,
  formatTimestamp,
  riskLevelTone,
  trustLevelLabels,
} from "../lib/format";
import { sortEventsByTimeDesc } from "../lib/events";

export function DashboardPage() {
  const overview = useTenantOverview();
  const stats = useTrustSessionStats();

  const recent = useMemo(
    () =>
      overview.data ? sortEventsByTimeDesc(overview.data.recentEvents) : [],
    [overview.data],
  );

  const fleetAnomalies = overview.data?.activeFleetAnomalies ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security overview"
        description="See how your apps are protected and spot anything that needs attention."
      />

      <Onboarding />

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat
          label="Apps"
          loading={overview.isLoading}
          value={overview.data ? overview.data.appCount : "—"}
          hint="Mobile or desktop apps registered to this tenant."
        />
        <Stat
          label="Webhooks"
          loading={overview.isLoading}
          value={overview.data ? overview.data.webhookCount : "—"}
          hint="Endpoints receiving signed event deliveries."
        />
        <Stat
          label="Events (24h)"
          loading={overview.isLoading}
          value={overview.data ? Number(overview.data.eventsLast24h) : "—"}
          hint="Risk and policy-decision events in the last 24 hours."
        />
        <Stat
          label="Trust sessions"
          loading={stats.isLoading}
          value={stats.data ? Number(stats.data.totalSessions) : "—"}
          hint="Devices that completed attestation and were issued a trust token."
        />
      </div>

      {fleetAnomalies.length > 0 && (
        <Card title="Fleet anomalies">
          <p className="mb-3 text-xs text-fg-muted">
            Cohorts whose population is currently showing a coordinated
            abuse-signal surge or a volume spike above its learned baseline. New
            attestations from these cohorts are stepped up automatically.
          </p>
          <ul className="divide-y divide-line">
            {fleetAnomalies.map((a, i) => (
              <li
                key={`${a.appId}-${a.buildHash}-${a.region}-${i}`}
                className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone="bg-amber-500/10 text-amber-700 border-amber-500/30 dark:bg-amber-500/15 dark:text-amber-300">
                    Surge
                  </Badge>
                  <span className="font-mono text-xs text-fg">{a.appId}</span>
                  {a.buildHash && (
                    <span className="font-mono text-xs text-fg-subtle">
                      build {a.buildHash.slice(0, 12)}
                    </span>
                  )}
                  {a.region && (
                    <span className="text-xs text-fg-subtle">{a.region}</span>
                  )}
                  {a.signals.map((s) => (
                    <Badge key={s}>{s}</Badge>
                  ))}
                  {a.velocitySurge && (
                    <Badge tone="bg-rose-500/10 text-rose-700 border-rose-500/30 dark:bg-rose-500/15 dark:text-rose-300">
                      velocity{" "}
                      {a.velocityRatio > 0
                        ? `${a.velocityRatio.toFixed(1)}×`
                        : "spike"}
                    </Badge>
                  )}
                </div>
                <span className="font-mono text-xs text-fg-subtle">
                  {a.maxSurgeRatio > 0
                    ? `${a.maxSurgeRatio.toFixed(1)}× baseline · `
                    : ""}
                  {Number(a.observed)} obs
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Recent events">
          {overview.isLoading ? (
            <SkeletonRows rows={4} />
          ) : overview.isError ? (
            <ErrorNotice
              error={overview.error}
              onRetry={() => void overview.refetch()}
            />
          ) : recent.length === 0 ? (
            <EmptyState>
              No recent events.{" "}
              <Link className="text-accent hover:underline" to="/events">
                Open events
              </Link>
            </EmptyState>
          ) : (
            <ul className="divide-y divide-line">
              {recent.slice(0, 8).map((e) => (
                <li
                  key={e.id}
                  className="flex items-center justify-between py-2 text-sm"
                >
                  <div className="flex items-center gap-2">
                    <Badge tone={riskLevelTone(e.riskLevel)}>
                      {trustLevelLabels[e.riskLevel]}
                    </Badge>
                    <span className="text-fg">
                      {eventTypeLabels[e.eventType]}
                    </span>
                  </div>
                  <span className="font-mono text-xs text-fg-subtle">
                    {formatTimestamp(e.timestamp)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Trust-session stats">
          {stats.isLoading ? (
            <SkeletonRows rows={4} />
          ) : stats.isError ? (
            <ErrorNotice
              error={stats.error}
              onRetry={() => void stats.refetch()}
            />
          ) : stats.data ? (
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-fg-muted">Tokens issued</span>
                <span className="text-fg-strong">
                  {Number(stats.data.tokensIssued)}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-fg-muted">Attestations failed</span>
                <span className="text-fg-strong">
                  {Number(stats.data.attestationsFailed)}
                </span>
              </div>
              <div className="pt-2">
                <div className="label">Sessions by trust level</div>
                <ul className="space-y-1">
                  {Object.entries(stats.data.sessionsByTrustLevel).map(
                    ([level, count]) => (
                      <li key={level} className="flex justify-between">
                        <span className="text-fg">{level}</span>
                        <span className="text-fg-strong">{Number(count)}</span>
                      </li>
                    ),
                  )}
                </ul>
              </div>
            </div>
          ) : (
            <EmptyState>No trust-session data.</EmptyState>
          )}
        </Card>
      </div>
    </div>
  );
}
