import { Badge, EmptyState } from "./ui";
import { healthBandLabel, healthBandTone } from "../lib/health";
import { formatRate, type TenantHealth } from "../lib/rollup";

// Renders the per-tenant health rows of a fleet rollup. Rows are pre-sorted
// worst-first by computeFleetRollup, so the operator sees tenants that need
// attention at the top. Degraded reads surface their reason inline instead of
// dropping the tenant.
export function TenantHealthTable({ tenants }: { tenants: TenantHealth[] }) {
  if (tenants.length === 0) {
    return <EmptyState>No tenants in the managed fleet.</EmptyState>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr>
            <th className="th">Tenant</th>
            <th className="th">Health</th>
            <th className="th">Score</th>
            <th className="th">App count</th>
            <th className="th">Events 24h</th>
            <th className="th">Sessions</th>
            <th className="th">High-risk</th>
            <th className="th">Attest. fail</th>
          </tr>
        </thead>
        <tbody>
          {tenants.map((t) => (
            <tr key={t.tenantId} className="border-t border-slate-800">
              <td className="td font-mono">
                <div className="truncate" title={t.tenantId}>
                  {t.tenantId}
                </div>
                {t.errors.length > 0 && (
                  <div className="mt-1 text-xs text-rose-300/80">
                    {t.errors.join("; ")}
                  </div>
                )}
              </td>
              <td className="td">
                <Badge tone={healthBandTone(t.band)}>
                  {healthBandLabel(t.band)}
                </Badge>
              </td>
              <td className="td tabular-nums">{t.healthScore}</td>
              <td className="td tabular-nums">{t.apps}</td>
              <td className="td tabular-nums">{t.events24h}</td>
              <td className="td tabular-nums">{t.sessions}</td>
              <td className="td tabular-nums">{formatRate(t.highRiskRate)}</td>
              <td className="td tabular-nums">
                {formatRate(t.attestationFailureRate)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
