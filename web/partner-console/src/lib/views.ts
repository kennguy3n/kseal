// Client-side persistence for saved views and the operator's working filter /
// sort / threshold state. Everything lives in localStorage (no server, no
// mutation) and is defensively validated on load so tampered or stale storage
// degrades to sane defaults rather than crashing the console.

import {
  DEFAULT_SORT,
  EMPTY_FILTER,
  type FilterState,
  type SortDir,
  type SortKey,
  type SortState,
} from "./filter";
import type { HealthBand } from "./rollup";
import { EMPTY_THRESHOLDS, type AlertThresholds } from "./thresholds";

export interface SavedView {
  id: string;
  name: string;
  filter: FilterState;
  sort: SortState;
  thresholds: AlertThresholds;
}

/** The operator's current working state, persisted across reloads. */
export interface FleetViewState {
  filter: FilterState;
  sort: SortState;
  thresholds: AlertThresholds;
}

const VIEWS_KEY = "kseal.partner.views.v1";
const STATE_KEY = "kseal.partner.viewstate.v1";

const HEALTH_BANDS: readonly HealthBand[] = [
  "healthy",
  "watch",
  "at-risk",
  "unknown",
];
const SORT_KEYS: readonly SortKey[] = [
  "health",
  "tenant",
  "apps",
  "events",
  "sessions",
  "highRisk",
  "attestFail",
];

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function bool(v: unknown): boolean {
  return v === true;
}

function optRate(v: unknown): number | undefined {
  if (typeof v !== "number" || !Number.isFinite(v)) return undefined;
  return Math.min(1, Math.max(0, v));
}

function optScore(v: unknown): number | undefined {
  if (typeof v !== "number" || !Number.isFinite(v)) return undefined;
  return Math.min(100, Math.max(0, Math.round(v)));
}

function sanitizeBands(v: unknown): HealthBand[] {
  if (!Array.isArray(v)) return [];
  const out: HealthBand[] = [];
  for (const b of v) {
    if (HEALTH_BANDS.includes(b as HealthBand) && !out.includes(b as HealthBand)) {
      out.push(b as HealthBand);
    }
  }
  return out;
}

export function sanitizeFilter(v: unknown): FilterState {
  const o = (v ?? {}) as Record<string, unknown>;
  return {
    search: str(o.search),
    bands: sanitizeBands(o.bands),
    region: str(o.region),
    onlyBreaching: bool(o.onlyBreaching),
  };
}

export function sanitizeSort(v: unknown): SortState {
  const o = (v ?? {}) as Record<string, unknown>;
  const key = SORT_KEYS.includes(o.key as SortKey)
    ? (o.key as SortKey)
    : DEFAULT_SORT.key;
  const dir: SortDir = o.dir === "asc" || o.dir === "desc" ? o.dir : DEFAULT_SORT.dir;
  return { key, dir };
}

export function sanitizeThresholds(v: unknown): AlertThresholds {
  const o = (v ?? {}) as Record<string, unknown>;
  const out: AlertThresholds = {};
  const minHealthScore = optScore(o.minHealthScore);
  const maxHighRiskRate = optRate(o.maxHighRiskRate);
  const maxAttestationFailureRate = optRate(o.maxAttestationFailureRate);
  if (minHealthScore !== undefined) out.minHealthScore = minHealthScore;
  if (maxHighRiskRate !== undefined) out.maxHighRiskRate = maxHighRiskRate;
  if (maxAttestationFailureRate !== undefined) {
    out.maxAttestationFailureRate = maxAttestationFailureRate;
  }
  return out;
}

function sanitizeView(v: unknown): SavedView | null {
  const o = (v ?? {}) as Record<string, unknown>;
  const id = str(o.id);
  const name = str(o.name).trim();
  if (!id || !name) return null;
  return {
    id,
    name,
    filter: sanitizeFilter(o.filter),
    sort: sanitizeSort(o.sort),
    thresholds: sanitizeThresholds(o.thresholds),
  };
}

export function loadViews(): SavedView[] {
  try {
    const raw = localStorage.getItem(VIEWS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const out: SavedView[] = [];
    for (const v of parsed) {
      const view = sanitizeView(v);
      if (view) out.push(view);
    }
    return out;
  } catch {
    return [];
  }
}

export function saveViews(views: readonly SavedView[]): void {
  try {
    localStorage.setItem(VIEWS_KEY, JSON.stringify(views));
  } catch {
    // Best-effort; the in-memory state remains the source of truth this session.
  }
}

export function loadViewState(): FleetViewState {
  try {
    const raw = localStorage.getItem(STATE_KEY);
    if (!raw) return defaultViewState();
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return {
      filter: sanitizeFilter(parsed.filter),
      sort: sanitizeSort(parsed.sort),
      thresholds: sanitizeThresholds(parsed.thresholds),
    };
  } catch {
    return defaultViewState();
  }
}

export function saveViewState(state: FleetViewState): void {
  try {
    localStorage.setItem(STATE_KEY, JSON.stringify(state));
  } catch {
    // Best-effort.
  }
}

export function defaultViewState(): FleetViewState {
  return {
    filter: { ...EMPTY_FILTER },
    sort: { ...DEFAULT_SORT },
    thresholds: { ...EMPTY_THRESHOLDS },
  };
}

/** Generates a reasonably-unique view id without pulling in a uuid dependency. */
export function newViewId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `v_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}
