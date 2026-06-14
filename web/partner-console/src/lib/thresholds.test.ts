import { describe, expect, it } from "vitest";
import {
  countBreaches,
  evaluateThresholds,
  hasActiveThresholds,
  isBreaching,
} from "./thresholds";
import { makeTenant } from "../test/fixtures";

describe("hasActiveThresholds", () => {
  it("detects whether any bound is set", () => {
    expect(hasActiveThresholds({})).toBe(false);
    expect(hasActiveThresholds({ minHealthScore: 50 })).toBe(true);
    expect(hasActiveThresholds({ maxHighRiskRate: 0.1 })).toBe(true);
  });
});

describe("evaluateThresholds", () => {
  it("flags a low health score", () => {
    const reasons = evaluateThresholds(
      makeTenant({ healthScore: 30, band: "at-risk" }),
      { minHealthScore: 50 },
    );
    expect(reasons).toHaveLength(1);
    expect(reasons[0]).toContain("health 30 < 50");
  });

  it("flags high-risk and attestation-failure rate breaches", () => {
    const reasons = evaluateThresholds(
      makeTenant({ highRiskRate: 0.2, attestationFailureRate: 0.15, band: "watch" }),
      { maxHighRiskRate: 0.1, maxAttestationFailureRate: 0.1 },
    );
    expect(reasons).toHaveLength(2);
    expect(reasons.join(" ")).toContain("high-risk 20.0% > 10.0%");
    expect(reasons.join(" ")).toContain("attest-fail 15.0% > 10.0%");
  });

  it("does not flag rate bounds for unknown/no-data tenants", () => {
    const reasons = evaluateThresholds(
      makeTenant({ band: "unknown", highRiskRate: 0, healthScore: 0 }),
      { maxHighRiskRate: 0.1 },
    );
    expect(reasons).toEqual([]);
  });

  it("still flags a min-health bound for unknown tenants (score 0)", () => {
    const reasons = evaluateThresholds(
      makeTenant({ band: "unknown", healthScore: 0 }),
      { minHealthScore: 50 },
    );
    expect(reasons).toHaveLength(1);
  });

  it("does not flag a tenant exactly at the bound", () => {
    expect(
      evaluateThresholds(makeTenant({ highRiskRate: 0.1, band: "watch" }), {
        maxHighRiskRate: 0.1,
      }),
    ).toEqual([]);
    expect(
      evaluateThresholds(makeTenant({ healthScore: 50 }), { minHealthScore: 50 }),
    ).toEqual([]);
  });
});

describe("isBreaching / countBreaches", () => {
  const tenants = [
    makeTenant({ tenantId: "a", healthScore: 10, band: "at-risk" }),
    makeTenant({ tenantId: "b", healthScore: 80, band: "healthy" }),
    makeTenant({ tenantId: "c", healthScore: 40, band: "watch" }),
  ];

  it("isBreaching reflects evaluateThresholds", () => {
    expect(isBreaching(tenants[0], { minHealthScore: 50 })).toBe(true);
    expect(isBreaching(tenants[1], { minHealthScore: 50 })).toBe(false);
  });

  it("countBreaches is 0 without active thresholds", () => {
    expect(countBreaches(tenants, {})).toBe(0);
  });

  it("countBreaches counts matching tenants", () => {
    expect(countBreaches(tenants, { minHealthScore: 50 })).toBe(2);
  });
});
