import { beforeEach, describe, expect, it } from "vitest";
import {
  defaultViewState,
  loadViewState,
  loadViews,
  newViewId,
  sanitizeFilter,
  sanitizeSort,
  sanitizeThresholds,
  saveViews,
  saveViewState,
  type SavedView,
} from "./views";

beforeEach(() => {
  localStorage.clear();
});

describe("sanitizeFilter", () => {
  it("coerces junk to safe defaults", () => {
    expect(sanitizeFilter(null)).toEqual({ search: "", bands: [], region: "", onlyBreaching: false });
    expect(
      sanitizeFilter({ search: 42, bands: ["healthy", "bogus", "healthy"], region: "US", onlyBreaching: "yes" }),
    ).toEqual({ search: "", bands: ["healthy"], region: "US", onlyBreaching: false });
  });

  it("keeps valid bands and drops duplicates", () => {
    expect(sanitizeFilter({ bands: ["at-risk", "watch", "at-risk"] }).bands).toEqual(["at-risk", "watch"]);
  });
});

describe("sanitizeSort", () => {
  it("falls back to the default sort for invalid input", () => {
    expect(sanitizeSort({ key: "nope", dir: "sideways" })).toEqual({ key: "health", dir: "asc" });
    expect(sanitizeSort({ key: "apps", dir: "desc" })).toEqual({ key: "apps", dir: "desc" });
  });
});

describe("sanitizeThresholds", () => {
  it("clamps rates to [0,1] and scores to [0,100], dropping invalid fields", () => {
    expect(sanitizeThresholds({ minHealthScore: 250, maxHighRiskRate: 5, maxAttestationFailureRate: -1 })).toEqual({
      minHealthScore: 100,
      maxHighRiskRate: 1,
      maxAttestationFailureRate: 0,
    });
    expect(sanitizeThresholds({ minHealthScore: "x" })).toEqual({});
    expect(sanitizeThresholds({ minHealthScore: 55.7 }).minHealthScore).toBe(56);
  });
});

describe("saved views persistence", () => {
  it("round-trips views through localStorage and drops invalid entries", () => {
    const views: SavedView[] = [
      { id: "1", name: "EU at-risk", filter: sanitizeFilter({ region: "DE" }), sort: sanitizeSort({ key: "apps", dir: "desc" }), thresholds: { minHealthScore: 50 } },
    ];
    saveViews(views);
    // Inject a malformed entry alongside the good one.
    const raw = JSON.parse(localStorage.getItem("kseal.partner.views.v1")!);
    raw.push({ id: "", name: "no id" });
    localStorage.setItem("kseal.partner.views.v1", JSON.stringify(raw));

    const loaded = loadViews();
    expect(loaded).toHaveLength(1);
    expect(loaded[0].name).toBe("EU at-risk");
    expect(loaded[0].filter.region).toBe("DE");
    expect(loaded[0].thresholds.minHealthScore).toBe(50);
  });

  it("returns [] when storage is empty or corrupt", () => {
    expect(loadViews()).toEqual([]);
    localStorage.setItem("kseal.partner.views.v1", "{not json");
    expect(loadViews()).toEqual([]);
  });
});

describe("view state persistence", () => {
  it("defaults when empty and round-trips a saved state", () => {
    expect(loadViewState()).toEqual(defaultViewState());
    saveViewState({
      filter: sanitizeFilter({ search: "alpha" }),
      sort: { key: "events", dir: "desc" },
      thresholds: { maxHighRiskRate: 0.2 },
    });
    const loaded = loadViewState();
    expect(loaded.filter.search).toBe("alpha");
    expect(loaded.sort).toEqual({ key: "events", dir: "desc" });
    expect(loaded.thresholds.maxHighRiskRate).toBe(0.2);
  });
});

describe("newViewId", () => {
  it("produces unique ids", () => {
    expect(newViewId()).not.toBe(newViewId());
  });
});
