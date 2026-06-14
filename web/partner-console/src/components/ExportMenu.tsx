import {
  buildFleetExport,
  exportFilename,
  fleetExportToJson,
  tenantsToCsv,
  triggerDownload,
} from "../lib/export";
import type { FleetRollup, TenantHealth } from "../lib/rollup";

// Exports the current (filtered) tenant view for reporting. CSV is the
// per-tenant table; JSON additionally captures the fleet rollup totals. The
// serialization lives in lib/export.ts; this component only wires the buttons.
export function ExportMenu({
  rollup,
  tenants,
}: {
  rollup: FleetRollup;
  tenants: readonly TenantHealth[];
}) {
  const disabled = tenants.length === 0;

  const onCsv = () => {
    triggerDownload(exportFilename("csv"), tenantsToCsv(tenants), "text/csv;charset=utf-8");
  };

  const onJson = () => {
    const json = fleetExportToJson(buildFleetExport(rollup, tenants));
    triggerDownload(exportFilename("json"), json, "application/json");
  };

  return (
    <div className="flex items-center gap-2" role="group" aria-label="Export current view">
      <button
        type="button"
        className="btn-ghost focus-ring"
        onClick={onCsv}
        disabled={disabled}
        title="Download the current tenant view as CSV"
      >
        Export CSV
      </button>
      <button
        type="button"
        className="btn-ghost focus-ring"
        onClick={onJson}
        disabled={disabled}
        title="Download the current view + fleet totals as JSON"
      >
        Export JSON
      </button>
    </div>
  );
}
