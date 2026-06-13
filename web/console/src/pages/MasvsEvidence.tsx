import { useMemo, useState } from "react";
import { useApps, useBuilds } from "../hooks/queries";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  LoadMore,
  Spinner,
} from "../components/ui";
import { formatTimestamp } from "../lib/format";
import { buildMasvsReport } from "../lib/masvs";

export function MasvsEvidencePage() {
  const apps = useApps();
  const [appId, setAppId] = useState("");
  const builds = useBuilds(appId);
  const [buildId, setBuildId] = useState("");

  // Default to the most recent build once builds load (or the selection becomes
  // stale after switching apps).
  const buildList = useMemo(() => builds.data ?? [], [builds.data]);
  const selectedBuild = useMemo(() => {
    if (buildList.length === 0) return null;
    return buildList.find((b) => b.id === buildId) ?? buildList[0];
  }, [buildList, buildId]);

  const report = useMemo(
    () => (selectedBuild ? buildMasvsReport(selectedBuild) : null),
    [selectedBuild],
  );

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-xl font-semibold text-slate-50">MASVS evidence</h1>
        <p className="text-sm text-slate-400">
          OWASP MASVS coverage for a release, derived from the registered
          build-proof manifest — the same evidence the report generator emits.
        </p>
      </header>

      <Card title="Release">
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <label htmlFor="masvsApp" className="label">
              App
            </label>
            <select
              id="masvsApp"
              className="input"
              value={appId}
              onChange={(e) => {
                setAppId(e.target.value);
                setBuildId("");
              }}
              disabled={apps.isLoading}
            >
              <option value="">Select an app…</option>
              {apps.data?.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="masvsBuild" className="label">
              Build
            </label>
            <select
              id="masvsBuild"
              className="input"
              value={selectedBuild?.id ?? ""}
              onChange={(e) => setBuildId(e.target.value)}
              disabled={!appId || buildList.length === 0}
            >
              {buildList.length === 0 && <option value="">No builds</option>}
              {buildList.map((b) => (
                <option key={b.id} value={b.id}>
                  {b.versionName || b.id} · {b.buildHash.slice(0, 12)}…
                </option>
              ))}
            </select>
          </div>
        </div>
        {appId && (
          <LoadMore
            hasNextPage={builds.hasNextPage}
            isFetchingNextPage={builds.isFetchingNextPage}
            onClick={() => void builds.fetchNextPage()}
          />
        )}
      </Card>

      {!appId ? (
        <EmptyState>Select an app to view its MASVS evidence.</EmptyState>
      ) : builds.isLoading ? (
        <Spinner />
      ) : builds.isError ? (
        <ErrorNotice error={builds.error} />
      ) : !report || !selectedBuild ? (
        <EmptyState>No builds registered for this app yet.</EmptyState>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            <Card title="Coverage">
              <div className="text-2xl font-semibold text-slate-50">
                {report.coveredCount}/{report.totalCategories}
              </div>
              <div className="mt-1 text-xs text-slate-400">
                MASVS categories with build evidence
              </div>
            </Card>
            <Card title="Version">
              <div className="text-sm text-slate-200">
                {report.versionName || "—"}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                code {report.versionCode}
              </div>
            </Card>
            <Card title="Build proof">
              <div
                className="break-all font-mono text-xs text-slate-300"
                title={report.buildHash}
              >
                {report.buildHash || "—"}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                registered {formatTimestamp(selectedBuild.createdAt)}
              </div>
            </Card>
          </div>

          <Card title="MASVS category coverage">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-800">
                    <th className="th">Category</th>
                    <th className="th">Status</th>
                    <th className="th">Evidencing modules</th>
                  </tr>
                </thead>
                <tbody>
                  {report.categories.map((c) => (
                    <tr
                      key={c.category}
                      className="border-b border-slate-800/60"
                    >
                      <td className="td font-medium text-slate-100">
                        MASVS-{c.category}
                      </td>
                      <td className="td">
                        {c.covered ? (
                          <Badge tone="bg-emerald-500/15 text-emerald-300 border-emerald-500/30">
                            Evidenced
                          </Badge>
                        ) : (
                          <Badge tone="bg-slate-500/15 text-slate-300 border-slate-500/30">
                            No build evidence
                          </Badge>
                        )}
                      </td>
                      <td className="td text-xs text-slate-400">
                        {c.modules.length > 0 ? c.modules.join(", ") : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card title="Applied transforms">
              {report.transforms.length === 0 ? (
                <EmptyState>
                  No build transforms recorded in the manifest.
                </EmptyState>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {report.transforms.map((t) => (
                    <span
                      key={t}
                      className="rounded-md border border-slate-700 px-2 py-0.5 font-mono text-xs text-slate-400"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </Card>
            <Card title="Gaps & notes">
              {report.gaps.length > 0 && (
                <div className="mb-3">
                  <div className="label">Categories without build evidence</div>
                  <div className="flex flex-wrap gap-1.5">
                    {report.gaps.map((g) => (
                      <Badge key={g}>MASVS-{g}</Badge>
                    ))}
                  </div>
                </div>
              )}
              <ul className="space-y-1 text-xs text-slate-400">
                {report.notes.map((n, i) => (
                  <li key={i}>• {n}</li>
                ))}
              </ul>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
