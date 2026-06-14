import { describe, expect, it } from "vitest";
import {
  buildFleetExport,
  csvField,
  exportFilename,
  fleetExportToJson,
  tenantsToCsv,
} from "./export";
import type { FleetRollup } from "./rollup";
import { makeTenant } from "../test/fixtures";

describe("csvField", () => {
  it("quotes fields containing commas, quotes, or newlines", () => {
    expect(csvField("plain")).toBe("plain");
    expect(csvField("a,b")).toBe('"a,b"');
    expect(csvField('he said "hi"')).toBe('"he said ""hi"""');
    expect(csvField("line1\nline2")).toBe('"line1\nline2"');
  });
});

describe("tenantsToCsv", () => {
  it("emits a header row and one row per tenant with CRLF endings", () => {
    const csv = tenantsToCsv([
      makeTenant({
        tenantId: "alpha",
        band: "at-risk",
        healthScore: 20,
        apps: 5,
        events24h: 12,
        sessions: 30,
        highRiskRate: 0.5,
        attestationFailureRate: 0.1,
        primaryRegion: "US",
      }),
    ]);
    const lines = csv.split("\r\n");
    expect(lines[0]).toBe(
      "tenant_id,status,health_band,health_score,apps,events_24h,sessions,high_risk_rate,attestation_failure_rate,primary_region,errors",
    );
    expect(lines[1]).toBe("alpha,ok,At risk,20,5,12,30,50.0%,10.0%,US,");
  });

  it("escapes error text that contains commas", () => {
    const csv = tenantsToCsv([
      makeTenant({ tenantId: "t", errors: ["overview: boom, retry"] }),
    ]);
    expect(csv).toContain('"overview: boom, retry"');
  });
});

const rollup: FleetRollup = {
  tenantCount: 1,
  healthyTenants: 0,
  degradedTenants: 0,
  bandCounts: { healthy: 0, watch: 0, "at-risk": 1, unknown: 0 },
  totalApps: 5,
  totalBuilds: 3,
  totalActivePolicies: 2,
  totalWebhooks: 1,
  totalEvents24h: 12,
  totalSessions: 30,
  totalTokensIssued: 25,
  totalAttestationsFailed: 1,
  sessionsByTrustLevel: { TRUSTED: 10, LOW_RISK: 5, MEDIUM_RISK: 5, HIGH_RISK: 8, CRITICAL: 2 },
  attestationFailureRate: 0.04,
  highRiskSessionRate: 0.33,
  mediumRiskSessionRate: 0.16,
  recentSignals: [],
  tenants: [],
};

describe("buildFleetExport / fleetExportToJson", () => {
  it("captures fleet totals and per-tenant rows with a deterministic timestamp", () => {
    const tenants = [makeTenant({ tenantId: "alpha", band: "at-risk", regions: ["US", "DE"] })];
    const exp = buildFleetExport(rollup, tenants, Date.UTC(2026, 5, 14, 0, 0, 0));
    expect(exp.generatedAt).toBe("2026-06-14T00:00:00.000Z");
    expect(exp.fleet.tenantCount).toBe(1);
    expect(exp.fleet.bandCounts["at-risk"]).toBe(1);
    expect(exp.tenants).toHaveLength(1);
    expect(exp.tenants[0].regions).toEqual(["US", "DE"]);

    // Round-trips through JSON without losing structure.
    const parsed = JSON.parse(fleetExportToJson(exp));
    expect(parsed.fleet.totalApps).toBe(5);
    expect(parsed.tenants[0].tenantId).toBe("alpha");
  });
});

describe("exportFilename", () => {
  it("builds a date-stamped filename", () => {
    expect(exportFilename("csv", Date.UTC(2026, 5, 14))).toBe("kseal-fleet-2026-06-14.csv");
    expect(exportFilename("json", Date.UTC(2026, 5, 14))).toBe("kseal-fleet-2026-06-14.json");
  });
});
