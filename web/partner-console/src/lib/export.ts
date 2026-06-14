// CSV / JSON export of the current tenant view for MSSP reporting. The
// serialization is pure (unit-testable); triggerDownload performs the DOM
// side-effect. Read-only: this exports exactly what the console already shows,
// computed client-side from the existing QueryService reads.

import { formatRate, type FleetRollup, type TenantHealth } from "./rollup";
import { healthBandLabel } from "./health";

const CSV_COLUMNS = [
  "tenant_id",
  "status",
  "health_band",
  "health_score",
  "apps",
  "events_24h",
  "sessions",
  "high_risk_rate",
  "attestation_failure_rate",
  "primary_region",
  "errors",
] as const;

/** RFC-4180 field escaping: quote when the value contains a comma, quote, or newline. */
export function csvField(value: string): string {
  if (/[",\r\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function rowFor(t: TenantHealth): string[] {
  return [
    t.tenantId,
    t.status,
    healthBandLabel(t.band),
    String(t.healthScore),
    String(t.apps),
    String(t.events24h),
    String(t.sessions),
    formatRate(t.highRiskRate),
    formatRate(t.attestationFailureRate),
    t.primaryRegion,
    t.errors.join("; "),
  ];
}

/** Serializes the tenant list to RFC-4180 CSV (CRLF line endings, header row). */
export function tenantsToCsv(tenants: readonly TenantHealth[]): string {
  const lines = [CSV_COLUMNS.join(",")];
  for (const t of tenants) {
    lines.push(rowFor(t).map(csvField).join(","));
  }
  return lines.join("\r\n");
}

export interface FleetExport {
  generatedAt: string;
  fleet: {
    tenantCount: number;
    bandCounts: FleetRollup["bandCounts"];
    totalApps: number;
    totalEvents24h: number;
    totalSessions: number;
    highRiskSessionRate: number;
    mediumRiskSessionRate: number;
    attestationFailureRate: number;
    sessionsByTrustLevel: FleetRollup["sessionsByTrustLevel"];
  };
  tenants: Array<{
    tenantId: string;
    status: string;
    band: string;
    healthScore: number;
    apps: number;
    events24h: number;
    sessions: number;
    highRiskRate: number;
    attestationFailureRate: number;
    primaryRegion: string;
    regions: string[];
    errors: string[];
  }>;
}

/**
 * Builds the structured JSON export of the fleet rollup + the (already filtered)
 * tenant rows. `nowMs` is injected for deterministic timestamps in tests.
 */
export function buildFleetExport(
  rollup: FleetRollup,
  tenants: readonly TenantHealth[],
  nowMs: number = Date.now(),
): FleetExport {
  return {
    generatedAt: new Date(nowMs).toISOString(),
    fleet: {
      tenantCount: rollup.tenantCount,
      bandCounts: rollup.bandCounts,
      totalApps: rollup.totalApps,
      totalEvents24h: rollup.totalEvents24h,
      totalSessions: rollup.totalSessions,
      highRiskSessionRate: rollup.highRiskSessionRate,
      mediumRiskSessionRate: rollup.mediumRiskSessionRate,
      attestationFailureRate: rollup.attestationFailureRate,
      sessionsByTrustLevel: rollup.sessionsByTrustLevel,
    },
    tenants: tenants.map((t) => ({
      tenantId: t.tenantId,
      status: t.status,
      band: t.band,
      healthScore: t.healthScore,
      apps: t.apps,
      events24h: t.events24h,
      sessions: t.sessions,
      highRiskRate: t.highRiskRate,
      attestationFailureRate: t.attestationFailureRate,
      primaryRegion: t.primaryRegion,
      regions: [...t.regions],
      errors: [...t.errors],
    })),
  };
}

export function fleetExportToJson(exp: FleetExport): string {
  return JSON.stringify(exp, null, 2);
}

/** A timestamped, filesystem-safe export filename, e.g. kseal-fleet-2026-06-14.csv. */
export function exportFilename(ext: "csv" | "json", nowMs: number = Date.now()): string {
  const date = new Date(nowMs).toISOString().slice(0, 10);
  return `kseal-fleet-${date}.${ext}`;
}

/**
 * Triggers a client-side file download via a transient object URL. DOM
 * side-effect; the serialization above is the testable part. Guards on
 * document presence so it is a no-op in non-DOM environments.
 */
export function triggerDownload(
  filename: string,
  content: string,
  mime: string,
): void {
  if (typeof document === "undefined" || typeof URL.createObjectURL !== "function") {
    return;
  }
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
