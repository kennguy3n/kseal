import { Link, useParams } from "react-router-dom";
import {
  useActivePolicy,
  useApp,
  useBuilds,
  useEvents,
} from "../hooks/queries";
import {
  Card,
  EmptyState,
  ErrorNotice,
  LoadMore,
  SkeletonRows,
  Badge,
} from "../components/ui";
import {
  enforcementModeLabels,
  eventTypeLabels,
  formatEpochSeconds,
  formatTimestamp,
  platformLabels,
  riskLevelTone,
  trustLevelLabels,
} from "../lib/format";
import { sortEventsByTimeDesc } from "../lib/events";

export function AppDetailPage() {
  const { appId = "" } = useParams();
  const app = useApp(appId);
  const builds = useBuilds(appId);
  const activePolicy = useActivePolicy(appId);
  const events = useEvents({ appId });

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <Link to="/apps" className="text-xs text-fg-muted hover:underline">
            ← Apps
          </Link>
          <h1 className="text-xl font-semibold text-fg-strong">
            {app.data?.name ?? (app.isLoading ? "…" : appId)}
          </h1>
          {app.data && (
            <p className="text-sm text-fg-muted">
              {platformLabels[app.data.platform]} ·{" "}
              <span className="font-mono">{app.data.packageId}</span>
            </p>
          )}
        </div>
        <Link to="/policies" className="btn-ghost">
          Edit policy
        </Link>
      </header>

      {app.isError && (
        <ErrorNotice error={app.error} onRetry={() => void app.refetch()} />
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Active policy">
          {activePolicy.isLoading ? (
            <SkeletonRows rows={2} />
          ) : activePolicy.isError ? (
            <ErrorNotice
              error={activePolicy.error}
              onRetry={() => void activePolicy.refetch()}
            />
          ) : activePolicy.data ? (
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-fg-muted">Name</dt>
                <dd className="text-fg-strong">{activePolicy.data.name}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-fg-muted">Version</dt>
                <dd className="text-fg-strong">v{activePolicy.data.version}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-fg-muted">Enforcement</dt>
                <dd>
                  <Badge>
                    {enforcementModeLabels[activePolicy.data.enforcementMode]}
                  </Badge>
                </dd>
              </div>
              <div>
                <dt className="text-fg-muted">Modules</dt>
                <dd className="mt-1 flex flex-wrap gap-1">
                  {activePolicy.data.modulesEnabled.length === 0 ? (
                    <span className="text-fg-subtle">none</span>
                  ) : (
                    activePolicy.data.modulesEnabled.map((m) => (
                      <Badge key={m}>{m}</Badge>
                    ))
                  )}
                </dd>
              </div>
            </dl>
          ) : (
            <EmptyState>
              No active policy.{" "}
              <Link className="text-accent hover:underline" to="/policies">
                Create one
              </Link>
            </EmptyState>
          )}
        </Card>

        <Card title="Builds">
          {builds.isLoading ? (
            <SkeletonRows rows={2} />
          ) : builds.isError ? (
            <ErrorNotice
              error={builds.error}
              onRetry={() => void builds.refetch()}
            />
          ) : !builds.data || builds.data.length === 0 ? (
            <EmptyState>No builds recorded.</EmptyState>
          ) : (
            <>
              <table className="w-full">
              <thead>
                <tr className="border-b border-line">
                  <th className="th">Version</th>
                  <th className="th">Build hash</th>
                  <th className="th">Created</th>
                </tr>
              </thead>
              <tbody>
                {builds.data.map((b) => (
                  <tr key={b.id} className="border-b border-line/60">
                    <td className="td">
                      {b.versionName} ({Number(b.versionCode)})
                    </td>
                    <td className="td font-mono text-xs text-fg-muted">
                      {b.buildHash.slice(0, 16)}…
                    </td>
                    <td className="td font-mono text-xs text-fg-subtle">
                      {formatEpochSeconds(b.createdAt)}
                    </td>
                  </tr>
                ))}
              </tbody>
              </table>
              <LoadMore
                hasNextPage={builds.hasNextPage}
                isFetchingNextPage={builds.isFetchingNextPage}
                onClick={() => void builds.fetchNextPage()}
              />
            </>
          )}
        </Card>
      </div>

      <Card title="Recent events">
        {events.isLoading ? (
          <SkeletonRows rows={3} />
        ) : events.isError ? (
          <ErrorNotice
            error={events.error}
            onRetry={() => void events.refetch()}
          />
        ) : !events.data || events.data.length === 0 ? (
          <EmptyState>No events for this app.</EmptyState>
        ) : (
          <ul className="divide-y divide-line">
            {sortEventsByTimeDesc(events.data)
              .slice(0, 12)
              .map((e) => (
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
    </div>
  );
}
