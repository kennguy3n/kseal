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

  return (
    <div className="space-y-6">
      <PageHeader
        title="Overview"
        description="Tenant trust posture at a glance."
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
