import { useMemo, useState } from "react";
import { useApps, useBuilds } from "../hooks/queries";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNotice,
  InfoHint,
  LoadMore,
  SkeletonRows,
} from "../components/ui";
import { formatEpochSeconds } from "../lib/format";
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
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <h1 className="text-xl font-semibold text-fg-strong">
              MASVS evidence
            </h1>
            <InfoHint label="About MASVS evidence">
              The OWASP Mobile Application Security Verification Standard (MASVS)
              defines security categories every mobile app should meet. kseal
              maps each protection your build applied to the categories it
              evidences, so a release’s coverage is derived from its signed
              build-proof manifest — not a self-assessment.
            </InfoHint>
          </div>
          <p className="mt-1 max-w-2xl text-sm text-fg-muted">
            OWASP MASVS coverage for a release, derived from the registered
            build-proof manifest — the same evidence the report generator
            emits.
          </p>
        </div>
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
        <SkeletonRows rows={4} />
      ) : builds.isError ? (
        <ErrorNotice
          error={builds.error}
          onRetry={() => void builds.refetch()}
        />
      ) : !report || !selectedBuild ? (
        <EmptyState>No builds registered for this app yet.</EmptyState>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-3">
            <Card title="Coverage">
              <div className="text-2xl font-semibold text-fg-strong">
                {report.coveredCount}/{report.totalCategories}
              </div>
              <div className="mt-1 text-xs text-fg-muted">
                MASVS categories with build evidence
              </div>
            </Card>
            <Card title="Version">
              <div className="text-sm text-fg">
                {report.versionName || "—"}
              </div>
              <div className="mt-1 text-xs text-fg-subtle">
                code {report.versionCode}
              </div>
            </Card>
            <Card title="Build proof">
              <div
                className="break-all font-mono text-xs text-fg"
                title={report.buildHash}
              >
                {report.buildHash || "—"}
              </div>
              <div className="mt-1 text-xs text-fg-subtle">
                registered {formatEpochSeconds(selectedBuild.createdAt)}
              </div>
            </Card>
          </div>

          <Card title="MASVS category coverage">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-line">
                    <th className="th">Category</th>
                    <th className="th">Status</th>
                    <th className="th">Evidencing modules</th>
                  </tr>
                </thead>
                <tbody>
                  {report.categories.map((c) => (
                    <tr
                      key={c.category}
                      className="border-b border-line/60"
                    >
                      <td className="td font-medium text-fg-strong">
                        MASVS-{c.category}
                      </td>
                      <td className="td">
                        {c.covered ? (
                          <Badge tone="bg-emerald-500/10 text-emerald-700 border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-300">
                            Evidenced
                          </Badge>
                        ) : (
                          <Badge tone="bg-fg-subtle/15 text-fg border-line-strong">
                            No build evidence
                          </Badge>
                        )}
                      </td>
                      <td className="td text-xs text-fg-muted">
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
                      className="rounded-md border border-line-strong px-2 py-0.5 font-mono text-xs text-fg-muted"
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
              <ul className="space-y-1 text-xs text-fg-muted">
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
