import { Link } from "react-router-dom";
import { useApps } from "../hooks/queries";
import {
  Card,
  EmptyState,
  ErrorNotice,
  LoadMore,
  Spinner,
  Badge,
} from "../components/ui";
import { platformLabels } from "../lib/format";

export function AppsListPage() {
  const apps = useApps();

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-fg-strong">Apps</h1>
        <p className="text-sm text-fg-muted">
          Registered applications for this tenant.
        </p>
      </header>

      <Card>
        {apps.isLoading ? (
          <Spinner />
        ) : apps.isError ? (
          <ErrorNotice error={apps.error} />
        ) : !apps.data || apps.data.length === 0 ? (
          <EmptyState>No apps registered yet.</EmptyState>
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
