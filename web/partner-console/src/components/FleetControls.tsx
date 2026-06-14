import { useEffect, useId, useState } from "react";
import type { HealthBand, FleetRollup } from "../lib/rollup";
import { isFilterActive, isSortActive, type FilterState } from "../lib/filter";
import { hasActiveThresholds } from "../lib/thresholds";
import { healthBandLabel, healthBandTone } from "../lib/health";
import type { SavedView } from "../lib/views";
import type { UseFleetViewResult } from "../hooks/useFleetView";
import { ThresholdsEditor } from "./ThresholdsEditor";
import { ExportMenu } from "./ExportMenu";

const BANDS: HealthBand[] = ["healthy", "watch", "at-risk", "unknown"];

// The MSSP console toolbar: quick filters (search, health bands, region,
// breaching-only), saved views, alert thresholds, and export — all client-side
// over the existing reads. Controlled by useFleetView.
export function FleetControls({
  view,
  rollup,
  regions,
}: {
  view: UseFleetViewResult;
  rollup: FleetRollup;
  regions: readonly string[];
}) {
  const { filter, sort, thresholds, setFilter, setThresholds } = view;
  const searchId = useId();
  const regionId = useId();
  // Show Reset whenever there is non-default state to clear: an active filter,
  // any threshold set (even with zero current breaches, so the operator can
  // always clear thresholds they configured), or a non-default sort — since
  // resetView restores the default sort too, Reset must be reachable for it.
  const active =
    isFilterActive(filter) || hasActiveThresholds(thresholds) || isSortActive(sort);

  const patch = (p: Partial<FilterState>) => setFilter({ ...filter, ...p });

  const toggleBand = (band: HealthBand) => {
    const has = filter.bands.includes(band);
    patch({
      bands: has ? filter.bands.filter((b) => b !== band) : [...filter.bands, band],
    });
  };

  return (
    <section
      aria-label="Fleet filters and views"
      className="card space-y-4"
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="flex-1">
          <label htmlFor={searchId} className="label">
            Search tenants
          </label>
          <input
            id={searchId}
            type="search"
            className="input"
            placeholder="Search by tenant ID or region…"
            value={filter.search}
            onChange={(e) => patch({ search: e.target.value })}
          />
        </div>
        <div className="w-full lg:w-56">
          <label htmlFor={regionId} className="label">
            Region
          </label>
          <select
            id={regionId}
            className="input"
            value={filter.region}
            onChange={(e) => patch({ region: e.target.value })}
          >
            <option value="">All regions</option>
            {regions.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium uppercase tracking-wide text-muted">
          Health
        </span>
        {BANDS.map((band) => {
          const on = filter.bands.includes(band);
          return (
            <button
              key={band}
              type="button"
              aria-pressed={on}
              onClick={() => toggleBand(band)}
              className={`badge focus-ring transition-colors ${
                on
                  ? healthBandTone(band)
                  : "border-line-strong bg-transparent text-muted hover:bg-hover"
              }`}
            >
              {healthBandLabel(band)}
            </button>
          );
        })}
        <label className="ml-2 flex items-center gap-2 text-sm text-content">
          <input
            type="checkbox"
            className="h-4 w-4 rounded border-line-strong bg-field text-accent focus-ring"
            checked={filter.onlyBreaching}
            onChange={(e) => patch({ onlyBreaching: e.target.checked })}
          />
          Breaching only
        </label>
        {active && (
          <button
            type="button"
            className="ml-auto text-sm text-accent-strong underline-offset-2 hover:underline focus-ring"
            onClick={view.resetView}
          >
            Reset
          </button>
        )}
      </div>

      <SavedViews
        views={view.views}
        onApply={view.applyView}
        onSave={view.saveView}
        onDelete={view.deleteView}
      />

      <ThresholdsEditor thresholds={thresholds} onChange={setThresholds} />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-subtle">
          Showing {view.filteredTenants.length} of {rollup.tenantCount} tenants
          {view.breachCount > 0 && ` · ${view.breachCount} breaching`}.
        </p>
        <ExportMenu rollup={rollup} tenants={view.filteredTenants} />
      </div>
    </section>
  );
}

function SavedViews({
  views,
  onApply,
  onSave,
  onDelete,
}: {
  views: SavedView[];
  onApply: (view: SavedView) => void;
  onSave: (name: string) => void;
  onDelete: (id: string) => void;
}) {
  const selectId = useId();
  const nameId = useId();
  const [selectedId, setSelectedId] = useState("");
  const [name, setName] = useState("");

  // Drop the selection if the underlying view was deleted elsewhere.
  useEffect(() => {
    if (selectedId && !views.some((v) => v.id === selectedId)) setSelectedId("");
  }, [views, selectedId]);

  const apply = (id: string) => {
    setSelectedId(id);
    const v = views.find((view) => view.id === id);
    if (v) onApply(v);
  };

  const save = () => {
    const trimmed = name.trim();
    if (!trimmed) return;
    onSave(trimmed);
    setName("");
  };

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
      <div className="sm:w-64">
        <label htmlFor={selectId} className="label">
          Saved views
        </label>
        <div className="flex gap-2">
          <select
            id={selectId}
            className="input"
            value={selectedId}
            onChange={(e) => apply(e.target.value)}
            disabled={views.length === 0}
          >
            <option value="">
              {views.length === 0 ? "No saved views" : "Apply a view…"}
            </option>
            {views.map((v) => (
              <option key={v.id} value={v.id}>
                {v.name}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn-ghost focus-ring"
            onClick={() => selectedId && onDelete(selectedId)}
            disabled={!selectedId}
            aria-label="Delete selected view"
            title="Delete selected view"
          >
            Delete
          </button>
        </div>
      </div>
      <div className="flex-1">
        <label htmlFor={nameId} className="label">
          Save current view
        </label>
        <div className="flex gap-2">
          <input
            id={nameId}
            className="input"
            placeholder="View name (e.g. EU at-risk)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                save();
              }
            }}
          />
          <button
            type="button"
            className="btn-primary focus-ring"
            onClick={save}
            disabled={name.trim() === ""}
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
