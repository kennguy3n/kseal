import { Card, Spinner } from "../components/ui";
import { TenantHealthTable } from "../components/TenantHealthTable";
import { useFleet } from "../hooks/fleet";

export function TenantsPage() {
  const { rollup, isLoading, isFetching, refetch } = useFleet();

  if (isLoading) {
    return (
      <div className="py-12">
        <Spinner label="Loading tenants…" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">Tenants</h1>
          <p className="mt-1 text-sm text-slate-400">
            {rollup.healthyTenants} healthy · {rollup.degradedTenants} degraded ·
            sorted worst-first.
          </p>
        </div>
        <button className="btn-ghost" onClick={refetch} disabled={isFetching}>
          {isFetching ? "Refreshing…" : "Refresh"}
        </button>
      </header>

      <Card>
        <TenantHealthTable tenants={rollup.tenants} />
      </Card>
    </div>
  );
}
