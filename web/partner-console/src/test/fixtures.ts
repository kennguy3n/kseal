import type { SignalRecord } from "../lib/events";
import type { TenantHealth } from "../lib/rollup";

/** Builds a TenantHealth with sensible defaults; override any field per test. */
export function makeTenant(partial: Partial<TenantHealth> = {}): TenantHealth {
  return {
    tenantId: "tenant-x",
    status: "ok",
    apps: 1,
    events24h: 0,
    sessions: 0,
    attestationFailureRate: 0,
    highRiskRate: 0,
    mediumRiskRate: 0,
    healthScore: 100,
    band: "healthy",
    primaryRegion: "",
    regions: [],
    recentSignals: [],
    errors: [],
    ...partial,
  };
}

/** Builds a SignalRecord with defaults; override any field per test. */
export function makeSignal(partial: Partial<SignalRecord> = {}): SignalRecord {
  return {
    id: "evt-1",
    appId: "app-1",
    eventType: 1,
    riskLevel: 1,
    region: "",
    timestampMs: 0,
    ...partial,
  };
}
