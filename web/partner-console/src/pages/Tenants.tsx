import { useMemo } from "react";
import { Card, Spinner } from "../components/ui";
import { TenantHealthTable } from "../components/TenantHealthTable";
import { FleetControls } from "../components/FleetControls";
import { useFleet } from "../hooks/fleet";
import { useFleetView } from "../hooks/useFleetView";
import { allRegions } from "../lib/filter";

export function TenantsPage() {
  const { rollup, isLoading, isFetching, refetch } = useFleet();
  const view = useFleetView(rollup);
  const regions = useMemo(() => allRegions(rollup.tenants), [rollup.tenants]);

  if (isLoading) {
    return (
      <div className="py-12">
        <Spinner label="Loading tenants…" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-heading">Tenants</h1>
          <p className="mt-1 text-sm text-muted">
            {rollup.healthyTenants} healthy · {rollup.degradedTenants} degraded ·
            filter, search, set alert thresholds, and export.
          </p>
        </div>
        <button className="btn-ghost focus-ring" onClick={refetch} disabled={isFetching}>
          {isFetching ? "Refreshing…" : "Refresh"}
        </button>
      </header>

      <FleetControls view={view} rollup={rollup} regions={regions} />

      <Card>
        <TenantHealthTable
          tenants={view.filteredTenants}
          sort={view.sort}
          onToggleSort={view.toggleSort}
          thresholds={view.thresholds}
        />
      </Card>
    </div>
  );
}
