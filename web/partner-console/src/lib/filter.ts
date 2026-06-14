// Pure filtering, search, and sorting over the per-tenant health list. No React
// and no network so it is unit-testable; the hooks/components layer holds the
// state and renders the result. Used by the fleet/tenants views and the export.

import type { HealthBand, TenantHealth } from "./rollup";
import type { AlertThresholds } from "./thresholds";
import { isBreaching } from "./thresholds";

export type SortKey =
  | "health"
  | "tenant"
  | "apps"
  | "events"
  | "sessions"
  | "highRisk"
  | "attestFail";

export type SortDir = "asc" | "desc";

export interface SortState {
  key: SortKey;
  dir: SortDir;
}

/**
 * Operator filter state. All fields are client-side and persistable (see
 * lib/views.ts). `bands` empty means "all bands"; `region` "" means "any
 * region"; `onlyBreaching` narrows to tenants breaching the active thresholds.
 */
export interface FilterState {
  search: string;
  bands: HealthBand[];
  region: string;
  onlyBreaching: boolean;
}

// Frozen so these shared module constants can't be mutated in place; callers
// that need a working copy must spread them (and deep-copy the bands array).
export const DEFAULT_SORT: SortState = Object.freeze({ key: "health", dir: "asc" });

// Deep-frozen: the bands array is frozen too so even an in-place push/splice on
// EMPTY_FILTER.bands throws rather than silently corrupting the shared constant.
const EMPTY_BANDS: HealthBand[] = Object.freeze([]) as unknown as HealthBand[];

export const EMPTY_FILTER: FilterState = Object.freeze({
  search: "",
  bands: EMPTY_BANDS,
  region: "",
  onlyBreaching: false,
});

/** True when `sort` differs from the default worst-first-by-health order. */
export function isSortActive(sort: SortState): boolean {
  return sort.key !== DEFAULT_SORT.key || sort.dir !== DEFAULT_SORT.dir;
}

/** True when `filter` would narrow the list (i.e. differs from EMPTY_FILTER). */
export function isFilterActive(filter: FilterState): boolean {
  return (
    filter.search.trim() !== "" ||
    filter.bands.length > 0 ||
    filter.region !== "" ||
    filter.onlyBreaching
  );
}

function matchesSearch(t: TenantHealth, q: string): boolean {
  if (q === "") return true;
  const needle = q.toLowerCase();
  if (t.tenantId.toLowerCase().includes(needle)) return true;
  for (const r of t.regions) {
    if (r.toLowerCase().includes(needle)) return true;
  }
  return false;
}

/**
 * Applies search + band + region + threshold-breach filters. Pure; returns a
 * new array and never mutates the input.
 */
export function applyFilters(
  tenants: readonly TenantHealth[],
  filter: FilterState,
  thresholds: AlertThresholds,
): TenantHealth[] {
  const q = filter.search.trim();
  const bandSet = new Set(filter.bands);
  return tenants.filter((t) => {
    if (!matchesSearch(t, q)) return false;
    if (bandSet.size > 0 && !bandSet.has(t.band)) return false;
    if (filter.region !== "" && !t.regions.includes(filter.region)) return false;
    if (filter.onlyBreaching && !isBreaching(t, thresholds)) return false;
    return true;
  });
}

function compareBy(key: SortKey, a: TenantHealth, b: TenantHealth): number {
  switch (key) {
    case "tenant":
      return a.tenantId.localeCompare(b.tenantId);
    case "apps":
      return a.apps - b.apps;
    case "events":
      return a.events24h - b.events24h;
    case "sessions":
      return a.sessions - b.sessions;
    case "highRisk":
      return a.highRiskRate - b.highRiskRate;
    case "attestFail":
      return a.attestationFailureRate - b.attestationFailureRate;
    case "health":
    default:
      return a.healthScore - b.healthScore;
  }
}

/**
 * Sorts a copy of `tenants` by the given key/direction. Ties always break by
 * tenant id (ascending) so ordering is deterministic regardless of input order.
 */
export function applySort(
  tenants: readonly TenantHealth[],
  sort: SortState,
): TenantHealth[] {
  const sign = sort.dir === "asc" ? 1 : -1;
  return [...tenants].sort((a, b) => {
    const primary = compareBy(sort.key, a, b) * sign;
    if (primary !== 0) return primary;
    return a.tenantId.localeCompare(b.tenantId);
  });
}

/** Collects the sorted, de-duplicated set of regions observed across tenants. */
export function allRegions(tenants: readonly TenantHealth[]): string[] {
  const set = new Set<string>();
  for (const t of tenants) for (const r of t.regions) set.add(r);
  return Array.from(set).sort((a, b) => a.localeCompare(b));
}
