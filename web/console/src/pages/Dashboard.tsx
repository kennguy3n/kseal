import { useMemo } from "react";
import { Link } from "react-router-dom";
import {
  useApps,
  useTenantOverview,
  useTrustSessionStats,
  useWebhooks,
} from "../hooks/queries";
import { Card, ErrorNotice, Spinner, Stat, Badge, EmptyState } from "../components/ui";
import {
  eventTypeLabels,
  formatTimestamp,
  riskLevelTone,
  trustLevelLabels,
} from "../lib/format";
import { sortEventsByTimeDesc } from "../lib/events";

export function DashboardPage() {
  const apps = useApps();
  const webhooks = useWebhooks();
  const overview = useTenantOverview();
  const stats = useTrustSessionStats();

  const recent = useMemo(
    () =>
      overview.data ? sortEventsByTimeDesc(overview.data.recentEvents) : [],
    [overview.data],
  );

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-50">Overview</h1>
        <p className="text-sm text-slate-400">
          Tenant trust posture at a glance.
        </p>
      </header>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat
          label="Apps"
          value={apps.isLoading ? "…" : apps.data ? apps.data.length : "—"}
        />
        <Stat
          label="Webhooks"
          value={
            webhooks.isLoading ? "…" : webhooks.data ? webhooks.data.length : "—"
          }
        />
        <Stat
          label="Events (24h)"
          value={
            overview.isLoading
              ? "…"
              : overview.data
                ? Number(overview.data.eventsLast24h)
                : "—"
          }
        />
        <Stat
          label="Trust sessions"
          value={
            stats.isLoading
              ? "…"
              : stats.data
                ? Number(stats.data.totalSessions)
                : "—"
          }
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Recent events">
          {overview.isLoading ? (
            <Spinner />
          ) : overview.isError ? (
            <ErrorNotice error={overview.error} />
          ) : recent.length === 0 ? (
            <EmptyState>
              No recent events.{" "}
              <Link className="text-indigo-300 hover:underline" to="/events">
                Open events
              </Link>
            </EmptyState>
          ) : (
            <ul className="divide-y divide-slate-800">
              {recent.slice(0, 8).map((e) => (
                <li
                  key={e.id}
                  className="flex items-center justify-between py-2 text-sm"
                >
                  <div className="flex items-center gap-2">
                    <Badge tone={riskLevelTone(e.riskLevel)}>
                      {trustLevelLabels[e.riskLevel]}
                    </Badge>
                    <span className="text-slate-200">
                      {eventTypeLabels[e.eventType]}
                    </span>
                  </div>
                  <span className="font-mono text-xs text-slate-500">
                    {formatTimestamp(e.timestamp)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Trust-session stats">
          {stats.isLoading ? (
            <Spinner />
          ) : stats.isError ? (
            <ErrorNotice error={stats.error} />
          ) : stats.data ? (
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Tokens issued</span>
                <span className="text-slate-100">
                  {Number(stats.data.tokensIssued)}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Attestations failed</span>
                <span className="text-slate-100">
                  {Number(stats.data.attestationsFailed)}
                </span>
              </div>
              <div className="pt-2">
                <div className="label">Sessions by trust level</div>
                <ul className="space-y-1">
                  {Object.entries(stats.data.sessionsByTrustLevel).map(
                    ([level, count]) => (
                      <li key={level} className="flex justify-between">
                        <span className="text-slate-300">{level}</span>
                        <span className="text-slate-100">{Number(count)}</span>
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
