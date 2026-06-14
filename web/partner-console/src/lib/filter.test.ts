import { describe, expect, it } from "vitest";
import {
  allRegions,
  applyFilters,
  applySort,
  DEFAULT_SORT,
  EMPTY_FILTER,
  isFilterActive,
  isSortActive,
  type FilterState,
} from "./filter";
import { EMPTY_THRESHOLDS } from "./thresholds";
import { makeTenant } from "../test/fixtures";

const tenants = [
  makeTenant({ tenantId: "alpha", band: "at-risk", healthScore: 20, apps: 5, regions: ["US"], primaryRegion: "US", highRiskRate: 0.5 }),
  makeTenant({ tenantId: "bravo", band: "healthy", healthScore: 95, apps: 2, regions: ["DE"], primaryRegion: "DE", highRiskRate: 0.0 }),
  makeTenant({ tenantId: "charlie", band: "watch", healthScore: 60, apps: 9, regions: ["US", "FR"], primaryRegion: "US", highRiskRate: 0.1 }),
];

const filter = (p: Partial<FilterState>): FilterState => ({ ...EMPTY_FILTER, ...p });

describe("isFilterActive", () => {
  it("is false for the empty filter and true once narrowed", () => {
    expect(isFilterActive(EMPTY_FILTER)).toBe(false);
    expect(isFilterActive(filter({ search: "a" }))).toBe(true);
    expect(isFilterActive(filter({ bands: ["healthy"] }))).toBe(true);
    expect(isFilterActive(filter({ region: "US" }))).toBe(true);
    expect(isFilterActive(filter({ onlyBreaching: true }))).toBe(true);
  });
});

describe("isSortActive", () => {
  it("is false for the default sort and true once changed", () => {
    expect(isSortActive(DEFAULT_SORT)).toBe(false);
    expect(isSortActive({ key: "apps", dir: "asc" })).toBe(true);
    expect(isSortActive({ key: DEFAULT_SORT.key, dir: "desc" })).toBe(true);
  });
});

describe("applyFilters", () => {
  it("matches search against tenant id and region, case-insensitively", () => {
    expect(applyFilters(tenants, filter({ search: "ALPHA" }), EMPTY_THRESHOLDS).map((t) => t.tenantId)).toEqual(["alpha"]);
    expect(applyFilters(tenants, filter({ search: "fr" }), EMPTY_THRESHOLDS).map((t) => t.tenantId)).toEqual(["charlie"]);
  });

  it("filters by health band set", () => {
    expect(
      applyFilters(tenants, filter({ bands: ["healthy", "watch"] }), EMPTY_THRESHOLDS).map((t) => t.tenantId),
    ).toEqual(["bravo", "charlie"]);
  });

  it("filters by region membership", () => {
    expect(applyFilters(tenants, filter({ region: "US" }), EMPTY_THRESHOLDS).map((t) => t.tenantId)).toEqual(["alpha", "charlie"]);
  });

  it("filters to only breaching tenants when requested", () => {
    const thresholds = { maxHighRiskRate: 0.2 };
    expect(
      applyFilters(tenants, filter({ onlyBreaching: true }), thresholds).map((t) => t.tenantId),
    ).toEqual(["alpha"]);
  });

  it("does not mutate the input array", () => {
    const copy = [...tenants];
    applyFilters(tenants, filter({ search: "alpha" }), EMPTY_THRESHOLDS);
    expect(tenants).toEqual(copy);
  });
});

describe("applySort", () => {
  it("sorts by health ascending by default (worst-first)", () => {
    expect(applySort(tenants, { key: "health", dir: "asc" }).map((t) => t.tenantId)).toEqual(["alpha", "charlie", "bravo"]);
  });

  it("sorts descending and by other keys", () => {
    expect(applySort(tenants, { key: "apps", dir: "desc" }).map((t) => t.tenantId)).toEqual(["charlie", "alpha", "bravo"]);
    expect(applySort(tenants, { key: "tenant", dir: "asc" }).map((t) => t.tenantId)).toEqual(["alpha", "bravo", "charlie"]);
  });

  it("breaks ties deterministically by tenant id", () => {
    const tied = [
      makeTenant({ tenantId: "zeta", healthScore: 50 }),
      makeTenant({ tenantId: "delta", healthScore: 50 }),
    ];
    expect(applySort(tied, { key: "health", dir: "asc" }).map((t) => t.tenantId)).toEqual(["delta", "zeta"]);
  });

  it("does not mutate the input array", () => {
    const copy = [...tenants];
    applySort(tenants, { key: "apps", dir: "desc" });
    expect(tenants).toEqual(copy);
  });
});

describe("allRegions", () => {
  it("returns the sorted union of tenant regions", () => {
    expect(allRegions(tenants)).toEqual(["DE", "FR", "US"]);
  });
});
