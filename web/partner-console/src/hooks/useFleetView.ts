import { useCallback, useEffect, useMemo, useState } from "react";
import {
  applyFilters,
  applySort,
  type FilterState,
  type SortKey,
  type SortState,
} from "../lib/filter";
import type { FleetRollup, TenantHealth } from "../lib/rollup";
import { countBreaches, type AlertThresholds } from "../lib/thresholds";
import {
  loadViewState,
  loadViews,
  newViewId,
  saveViewState,
  saveViews,
  type SavedView,
} from "../lib/views";

export interface UseFleetViewResult {
  filter: FilterState;
  sort: SortState;
  thresholds: AlertThresholds;
  views: SavedView[];
  /** Tenants after filter + sort, ready to render/export. */
  filteredTenants: TenantHealth[];
  /** Number of (filtered) tenants breaching the active thresholds. */
  breachCount: number;
  setFilter: (next: FilterState) => void;
  setSort: (next: SortState) => void;
  /** Toggles a column sort: same key flips direction, new key resets to asc. */
  toggleSort: (key: SortKey) => void;
  setThresholds: (next: AlertThresholds) => void;
  saveView: (name: string) => void;
  deleteView: (id: string) => void;
  applyView: (view: SavedView) => void;
  resetView: () => void;
}

/**
 * Owns the operator's working view state (filter / sort / thresholds) and the
 * set of saved views, persisting both to localStorage, and derives the
 * filtered + sorted tenant list from a fleet rollup. Kept separate from the
 * data-fetching `useFleet` hook so presentation state and server state evolve
 * independently.
 */
export function useFleetView(rollup: FleetRollup): UseFleetViewResult {
  const [{ filter, sort, thresholds }, setState] = useState(() => loadViewState());
  const [views, setViews] = useState<SavedView[]>(() => loadViews());

  useEffect(() => {
    saveViewState({ filter, sort, thresholds });
  }, [filter, sort, thresholds]);

  const setFilter = useCallback((next: FilterState) => {
    setState((s) => ({ ...s, filter: next }));
  }, []);

  const setSort = useCallback((next: SortState) => {
    setState((s) => ({ ...s, sort: next }));
  }, []);

  const toggleSort = useCallback((key: SortKey) => {
    setState((s) => ({
      ...s,
      sort:
        s.sort.key === key
          ? { key, dir: s.sort.dir === "asc" ? "desc" : "asc" }
          : { key, dir: "asc" },
    }));
  }, []);

  const setThresholds = useCallback((next: AlertThresholds) => {
    setState((s) => ({ ...s, thresholds: next }));
  }, []);

  const persistViews = useCallback((next: SavedView[]) => {
    setViews(next);
    saveViews(next);
  }, []);

  const saveView = useCallback(
    (name: string) => {
      const trimmed = name.trim();
      if (!trimmed) return;
      const view: SavedView = {
        id: newViewId(),
        name: trimmed,
        filter,
        sort,
        thresholds,
      };
      // Replace a same-named view rather than accumulating duplicates.
      setViews((prev) => {
        const next = [...prev.filter((v) => v.name !== trimmed), view].sort(
          (a, b) => a.name.localeCompare(b.name),
        );
        saveViews(next);
        return next;
      });
    },
    [filter, sort, thresholds],
  );

  const deleteView = useCallback(
    (id: string) => {
      persistViews(views.filter((v) => v.id !== id));
    },
    [persistViews, views],
  );

  const applyView = useCallback((view: SavedView) => {
    setState({
      filter: view.filter,
      sort: view.sort,
      thresholds: view.thresholds,
    });
  }, []);

  const resetView = useCallback(() => {
    setState(() => ({
      filter: { search: "", bands: [], region: "", onlyBreaching: false },
      sort: { key: "health", dir: "asc" },
      thresholds: {},
    }));
  }, []);

  const filteredTenants = useMemo(
    () => applySort(applyFilters(rollup.tenants, filter, thresholds), sort),
    [rollup.tenants, filter, thresholds, sort],
  );

  const breachCount = useMemo(
    () => countBreaches(filteredTenants, thresholds),
    [filteredTenants, thresholds],
  );

  return {
    filter,
    sort,
    thresholds,
    views,
    filteredTenants,
    breachCount,
    setFilter,
    setSort,
    toggleSort,
    setThresholds,
    saveView,
    deleteView,
    applyView,
    resetView,
  };
}
