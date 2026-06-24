import { Link } from "react-router-dom";
import { useApps } from "../hooks/queries";
import {
  Card,
  EmptyState,
  ErrorNotice,
  LoadMore,
  PageHeader,
  SkeletonRows,
  Badge,
} from "../components/ui";
import { platformLabels } from "../lib/format";
import { docs } from "../lib/links";

export function AppsListPage() {
  const apps = useApps();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Your apps"
        description="The apps you protect with kseal. Each one gets its own SDK keys and policies."
      />

      <Card>
        {apps.isLoading ? (
          <SkeletonRows rows={4} />
        ) : apps.isError ? (
          <ErrorNotice
            error={apps.error}
            onRetry={() => void apps.refetch()}
          />
        ) : !apps.data || apps.data.length === 0 ? (
          <EmptyState
            title="No apps registered yet"
            action={
              <a
                href={docs.quickstart()}
                target="_blank"
                rel="noreferrer"
                className="btn-primary"
              >
                Open the quickstart
              </a>
            }
          >
            Register your first app with the kseal CLI to get its app ID and
            signing keys, then integrate the SDK.
          </EmptyState>
        ) : (
          <>
            <table className="w-full">
            <thead>
              <tr className="border-b border-line">
                <th className="th">Name</th>
                <th className="th">Platform</th>
                <th className="th">Package ID</th>
                <th className="th">Status</th>
              </tr>
            </thead>
            <tbody>
              {apps.data.map((app) => (
                <tr
                  key={app.id}
                  className="border-b border-line/60 hover:bg-elevated/40"
                >
                  <td className="td">
                    <Link
                      to={`/apps/${app.id}`}
                      className="font-medium text-accent hover:underline"
                    >
                      {app.name}
                    </Link>
                  </td>
                  <td className="td">{platformLabels[app.platform]}</td>
                  <td className="td font-mono text-xs text-fg-muted">
                    {app.packageId}
                  </td>
                  <td className="td">
                    <Badge>{app.status || "unknown"}</Badge>
                  </td>
                </tr>
              ))}
            </tbody>
            </table>
            <LoadMore
              hasNextPage={apps.hasNextPage}
              isFetchingNextPage={apps.isFetchingNextPage}
              onClick={() => void apps.fetchNextPage()}
            />
          </>
        )}
      </Card>
    </div>
  );
}
