import { Link } from "react-router-dom";
import { Badge, EmptyState } from "./ui";
import { Sparkline } from "./Sparkline";
import { healthBandLabel, healthBandTone } from "../lib/health";
import { formatRate, type TenantHealth } from "../lib/rollup";
import { bucketSignals } from "../lib/events";
import type { SortKey, SortState } from "../lib/filter";
import { evaluateThresholds, type AlertThresholds } from "../lib/thresholds";

const ACTIVITY_SPAN_MS = 24 * 60 * 60 * 1000;
const ACTIVITY_BUCKETS = 12;

interface Column {
  key: SortKey | null;
  label: string;
  align?: "left" | "right";
}

const COLUMNS: Column[] = [
  { key: "tenant", label: "Tenant" },
  { key: "health", label: "Health" },
  { key: null, label: "Score", align: "right" },
  { key: null, label: "Region" },
  { key: "apps", label: "Apps", align: "right" },
  { key: "events", label: "Events 24h", align: "right" },
  { key: "sessions", label: "Sessions", align: "right" },
  { key: "highRisk", label: "High-risk", align: "right" },
  { key: "attestFail", label: "Attest. fail", align: "right" },
  { key: null, label: "Activity" },
];

// Renders the per-tenant health rows of a fleet rollup. Columns are sortable,
// each tenant links to its drill-down, rows breaching the active alert
// thresholds are flagged, and a sparkline shows recent signal activity.
// Degraded reads surface their reason inline instead of dropping the tenant.
export function TenantHealthTable({
  tenants,
  sort,
  onToggleSort,
  thresholds = {},
  nowMs = Date.now(),
}: {
  tenants: TenantHealth[];
  sort?: SortState;
  onToggleSort?: (key: SortKey) => void;
  thresholds?: AlertThresholds;
  nowMs?: number;
}) {
  if (tenants.length === 0) {
    return <EmptyState>No tenants match the current filters.</EmptyState>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <caption className="sr-only">
          Managed tenants, sorted worst-first by health unless re-sorted.
        </caption>
        <thead>
          <tr>
            {COLUMNS.map((col) => (
              <HeaderCell
                key={col.label}
                col={col}
                sort={sort}
                onToggleSort={onToggleSort}
              />
            ))}
          </tr>
        </thead>
        <tbody>
          {tenants.map((t) => {
            const breaches = evaluateThresholds(t, thresholds);
            const buckets = bucketSignals(
              t.recentSignals,
              nowMs,
              ACTIVITY_SPAN_MS,
              ACTIVITY_BUCKETS,
            );
            return (
              <tr
                key={t.tenantId}
                className={`border-t border-line ${
                  breaches.length > 0
                    ? "bg-rose-500/5 dark:bg-rose-500/10"
                    : "hover:bg-hover"
                }`}
              >
                <td className="td font-mono">
                  <Link
                    to={`/tenants/${encodeURIComponent(t.tenantId)}`}
                    className="focus-ring rounded text-accent-strong hover:underline"
                  >
                    <span className="block max-w-[14rem] truncate" title={t.tenantId}>
                      {t.tenantId}
                    </span>
                  </Link>
                  {breaches.length > 0 && (
                    <div
                      className="mt-1 text-xs font-medium text-rose-600 dark:text-rose-300"
                      title={breaches.join("; ")}
                    >
                      ⚠ {breaches.join("; ")}
                    </div>
                  )}
                  {t.errors.length > 0 && (
                    <div className="mt-1 text-xs text-rose-600/80 dark:text-rose-300/80">
                      {t.errors.join("; ")}
                    </div>
                  )}
                </td>
                <td className="td">
                  <Badge tone={healthBandTone(t.band)}>
                    {healthBandLabel(t.band)}
                  </Badge>
                </td>
                <td className="td text-right tabular-nums">{t.healthScore}</td>
                <td className="td text-muted">{t.primaryRegion || "—"}</td>
                <td className="td text-right tabular-nums">{t.apps}</td>
                <td className="td text-right tabular-nums">{t.events24h}</td>
                <td className="td text-right tabular-nums">{t.sessions}</td>
                <td className="td text-right tabular-nums">
                  {formatRate(t.highRiskRate)}
                </td>
                <td className="td text-right tabular-nums">
                  {formatRate(t.attestationFailureRate)}
                </td>
                <td className="td">
                  <Sparkline
                    buckets={buckets}
                    label={`${t.tenantId} recent activity`}
                    width={96}
                    height={24}
                  />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function HeaderCell({
  col,
  sort,
  onToggleSort,
}: {
  col: Column;
  sort?: SortState;
  onToggleSort?: (key: SortKey) => void;
}) {
  const alignClass = col.align === "right" ? "text-right" : "text-left";
  const sortable = col.key !== null && onToggleSort !== undefined;
  if (!sortable) {
    return <th className={`th ${alignClass}`}>{col.label}</th>;
  }
  const isActive = sort?.key === col.key;
  const arrow = isActive ? (sort?.dir === "asc" ? "▲" : "▼") : "";
  return (
    <th
      className={`th ${alignClass}`}
      aria-sort={
        isActive ? (sort?.dir === "asc" ? "ascending" : "descending") : "none"
      }
    >
      <button
        type="button"
        onClick={() => onToggleSort(col.key as SortKey)}
        className="focus-ring inline-flex items-center gap-1 rounded hover:text-content"
      >
        {col.label}
        <span aria-hidden="true" className="text-[0.6rem] text-accent-strong">
          {arrow}
        </span>
      </button>
    </th>
  );
}
