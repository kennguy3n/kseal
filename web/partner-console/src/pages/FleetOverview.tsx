import { Card, Spinner, Stat } from "../components/ui";
import { TenantHealthTable } from "../components/TenantHealthTable";
import { useFleet } from "../hooks/fleet";
import { formatRate, TRUST_LEVEL_KEYS } from "../lib/rollup";
import { trustLevelLabels } from "../lib/format";
import { TrustLevel } from "../gen/kseal/v1/common_pb";

const TRUST_LEVEL_ENUM: Record<string, TrustLevel> = {
  TRUSTED: TrustLevel.TRUSTED,
  LOW_RISK: TrustLevel.LOW_RISK,
  MEDIUM_RISK: TrustLevel.MEDIUM_RISK,
  HIGH_RISK: TrustLevel.HIGH_RISK,
  CRITICAL: TrustLevel.CRITICAL,
};

export function FleetOverviewPage() {
  const { rollup, isLoading, isFetching, refetch } = useFleet();

  if (isLoading) {
    return (
      <div className="py-12">
        <Spinner label="Loading fleet…" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-50">Fleet overview</h1>
          <p className="mt-1 text-sm text-slate-400">
            Aggregated client-side across {rollup.tenantCount} managed tenant
            {rollup.tenantCount === 1 ? "" : "s"}.
          </p>
        </div>
        <button className="btn-ghost" onClick={refetch} disabled={isFetching}>
          {isFetching ? "Refreshing…" : "Refresh"}
        </button>
      </header>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Stat label="Managed tenants" value={rollup.tenantCount} />
        <Stat label="Apps" value={rollup.totalApps} />
        <Stat label="Events (24h)" value={rollup.totalEvents24h} />
        <Stat label="Trust sessions" value={rollup.totalSessions} />
      </div>

      {rollup.degradedTenants > 0 && (
        <div
          role="alert"
          className="rounded-lg border border-amber-700/50 bg-amber-900/20 p-4 text-sm text-amber-200"
        >
          {rollup.degradedTenants} of {rollup.tenantCount} tenants returned
          incomplete data; their rows show the reason below. Aggregates include
          whatever each tenant did return.
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card title="Enforcement pressure">
          <dl className="space-y-3 text-sm">
            <Row
              label="High-risk session rate"
              value={formatRate(rollup.highRiskSessionRate)}
            />
            <Row
              label="Step-up session rate (proxy)"
              value={formatRate(rollup.mediumRiskSessionRate)}
            />
            <Row
              label="Attestation failure rate"
              value={formatRate(rollup.attestationFailureRate)}
            />
          </dl>
          <p className="mt-4 text-xs text-slate-500">
            The server does not expose explicit block / step-up decision counts,
            so these are approximated from the trust-level session distribution
            and attestation failures (see docs/mssp-console.md).
          </p>
        </Card>

        <Card title="Trust-level distribution">
          <dl className="space-y-2 text-sm">
            {TRUST_LEVEL_KEYS.map((key) => (
              <Row
                key={key}
                label={trustLevelLabels[TRUST_LEVEL_ENUM[key]]}
                value={rollup.sessionsByTrustLevel[key]}
              />
            ))}
          </dl>
        </Card>
      </div>

      <Card title="Tenant health">
        <TenantHealthTable tenants={rollup.tenants} />
      </Card>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between">
      <dt className="text-slate-400">{label}</dt>
      <dd className="font-medium tabular-nums text-slate-100">{value}</dd>
    </div>
  );
}
