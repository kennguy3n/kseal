import { describe, expect, it } from "vitest";
import {
  computeFleetRollup,
  formatRate,
  safeRate,
  tenantHealthFromSnapshot,
  tenantHealthScore,
  toNum,
  type TenantSnapshot,
} from "./rollup";

function snapshot(overrides: Partial<TenantSnapshot> & { tenantId: string }): TenantSnapshot {
  return { status: "ok", errors: [], ...overrides };
}

describe("toNum", () => {
  it("narrows bigint and guards non-finite/negative", () => {
    expect(toNum(5n)).toBe(5);
    expect(toNum(7)).toBe(7);
    expect(toNum(undefined)).toBe(0);
    expect(toNum(-3)).toBe(0);
    expect(toNum(Number.NaN)).toBe(0);
  });
});

describe("safeRate", () => {
  it("returns 0 on zero denominator and clamps to [0,1]", () => {
    expect(safeRate(1, 0)).toBe(0);
    expect(safeRate(1, 4)).toBe(0.25);
    expect(safeRate(5, 4)).toBe(1);
    expect(safeRate(-1, 4)).toBe(0);
  });
});

describe("tenantHealthScore", () => {
  it("scores a clean tenant 100 / healthy", () => {
    const { healthScore, band } = tenantHealthScore({
      status: "ok",
      highRiskRate: 0,
      attestationFailureRate: 0,
      mediumRiskRate: 0,
      hasData: true,
    });
    expect(healthScore).toBe(100);
    expect(band).toBe("healthy");
  });

  it("bands a high-risk tenant as at-risk", () => {
    const { healthScore, band } = tenantHealthScore({
      status: "ok",
      highRiskRate: 0.9,
      attestationFailureRate: 0.2,
      mediumRiskRate: 0.1,
      hasData: true,
    });
    expect(healthScore).toBeLessThan(50);
    expect(band).toBe("at-risk");
  });

  it("treats no-data / error tenants as unknown, not healthy", () => {
    expect(tenantHealthScore({
      status: "error",
      highRiskRate: 0,
      attestationFailureRate: 0,
      mediumRiskRate: 0,
      hasData: false,
    })).toEqual({ healthScore: 0, band: "unknown" });
  });
});

describe("tenantHealthFromSnapshot", () => {
  it("derives rates from trust stats", () => {
    const h = tenantHealthFromSnapshot(
      snapshot({
        tenantId: "t1",
        overview: { appCount: 3, buildCount: 9, activePolicyCount: 1, webhookCount: 2, eventsLast24h: 120 },
        trust: {
          totalSessions: 100,
          tokensIssued: 80,
          attestationsFailed: 8,
          sessionsByTrustLevel: { TRUSTED: 60, MEDIUM_RISK: 20, HIGH_RISK: 15, CRITICAL: 5 },
        },
      }),
    );
    expect(h.apps).toBe(3);
    expect(h.events24h).toBe(120);
    expect(h.highRiskRate).toBeCloseTo(0.2); // (15+5)/100
    expect(h.mediumRiskRate).toBeCloseTo(0.2);
    expect(h.attestationFailureRate).toBeCloseTo(0.1); // 8/80
    expect(h.band).toBe("healthy"); // penalty 0.17 -> score 83
  });

  it("bands a tenant with apps but no trust signal as unknown, not healthy", () => {
    // Reads succeeded, but there are zero sessions and zero tokens: there is no
    // basis to score health, so it must surface as unknown rather than 100.
    const h = tenantHealthFromSnapshot(
      snapshot({
        tenantId: "fresh",
        overview: { appCount: 3, buildCount: 40, activePolicyCount: 2, webhookCount: 0, eventsLast24h: 0 },
        trust: { totalSessions: 0, tokensIssued: 0, attestationsFailed: 0, sessionsByTrustLevel: {} },
      }),
    );
    expect(h.healthScore).toBe(0);
    expect(h.band).toBe("unknown");
  });
});

describe("computeFleetRollup", () => {
  it("aggregates totals and trust-level distribution across tenants", () => {
    const snaps: TenantSnapshot[] = [
      snapshot({
        tenantId: "t1",
        overview: { appCount: 2, buildCount: 4, activePolicyCount: 1, webhookCount: 1, eventsLast24h: 100 },
        trust: { totalSessions: 50, tokensIssued: 40, attestationsFailed: 4, sessionsByTrustLevel: { TRUSTED: 40, HIGH_RISK: 10 } },
      }),
      snapshot({
        tenantId: "t2",
        overview: { appCount: 3, buildCount: 6, activePolicyCount: 2, webhookCount: 0, eventsLast24h: 200 },
        trust: { totalSessions: 50, tokensIssued: 60, attestationsFailed: 6, sessionsByTrustLevel: { TRUSTED: 45, CRITICAL: 5 } },
      }),
    ];
    const r = computeFleetRollup(snaps);
    expect(r.tenantCount).toBe(2);
    expect(r.healthyTenants).toBe(2);
    expect(r.totalApps).toBe(5);
    expect(r.totalEvents24h).toBe(300);
    expect(r.totalSessions).toBe(100);
    expect(r.totalTokensIssued).toBe(100);
    expect(r.totalAttestationsFailed).toBe(10);
    expect(r.sessionsByTrustLevel.TRUSTED).toBe(85);
    expect(r.sessionsByTrustLevel.HIGH_RISK).toBe(10);
    expect(r.sessionsByTrustLevel.CRITICAL).toBe(5);
    expect(r.attestationFailureRate).toBeCloseTo(0.1); // 10/100
    expect(r.highRiskSessionRate).toBeCloseTo(0.15); // (10+5)/100
  });

  it("counts degraded tenants and still aggregates partial data", () => {
    const snaps: TenantSnapshot[] = [
      snapshot({
        tenantId: "ok",
        overview: { appCount: 1, buildCount: 1, activePolicyCount: 1, webhookCount: 1, eventsLast24h: 10 },
        trust: { totalSessions: 10, tokensIssued: 10, attestationsFailed: 0, sessionsByTrustLevel: { TRUSTED: 10 } },
      }),
      snapshot({
        tenantId: "partial",
        status: "partial",
        overview: { appCount: 4, buildCount: 0, activePolicyCount: 0, webhookCount: 0, eventsLast24h: 5 },
        errors: ["trust-stats: unavailable"],
      }),
      snapshot({ tenantId: "down", status: "error", errors: ["overview: permission denied", "trust-stats: permission denied"] }),
    ];
    const r = computeFleetRollup(snaps);
    expect(r.tenantCount).toBe(3);
    expect(r.healthyTenants).toBe(1);
    expect(r.degradedTenants).toBe(2);
    expect(r.totalApps).toBe(5); // 1 + 4, down contributes 0
    // worst-first ordering: the errored tenant (score 0) sorts first.
    expect(r.tenants[0].tenantId).toBe("down");
    expect(r.tenants[0].band).toBe("unknown");
  });

  it("ignores unknown trust-level keys without throwing", () => {
    const r = computeFleetRollup([
      snapshot({
        tenantId: "t",
        trust: { totalSessions: 5, tokensIssued: 5, attestationsFailed: 0, sessionsByTrustLevel: { BOGUS: 99, TRUSTED: 5 } },
      }),
    ]);
    expect(r.sessionsByTrustLevel.TRUSTED).toBe(5);
    expect(Object.values(r.sessionsByTrustLevel).reduce((a, b) => a + b, 0)).toBe(5);
  });

  it("handles an empty fleet", () => {
    const r = computeFleetRollup([]);
    expect(r.tenantCount).toBe(0);
    expect(r.totalSessions).toBe(0);
    expect(r.attestationFailureRate).toBe(0);
    expect(r.tenants).toEqual([]);
  });
});

describe("formatRate", () => {
  it("renders one-decimal percentages", () => {
    expect(formatRate(0)).toBe("0.0%");
    expect(formatRate(0.1234)).toBe("12.3%");
    expect(formatRate(1)).toBe("100.0%");
  });
});
