// Client-side multi-tenant rollups for the partner / MSSP console.
//
// The kseal server exposes only per-tenant, tenant-scoped reads (QueryService
// GetTenantOverview + GetTrustSessionStats). A partner managing many tenants
// therefore fetches each tenant independently and aggregates here, in the
// browser — there is no fleet RPC. These functions are deliberately pure (no
// network, no React) so the aggregation and the derived health scoring are unit
// -testable in isolation; the hooks layer only fetches and feeds them.
//
// Data gap (flagged, no server change): the existing RPCs do not expose explicit
// per-decision block / step-up counts. We approximate fleet enforcement pressure
// from the trust-level session distribution (high-risk and medium-risk shares)
// and the attestation-failure rate, which ARE exposed. See docs/mssp-console.md.

// Short TrustLevel keys as returned by GetTrustSessionStats.sessions_by_trust_level
// (server trims the TRUST_LEVEL_ prefix).
export const TRUST_LEVEL_KEYS = [
  "TRUSTED",
  "LOW_RISK",
  "MEDIUM_RISK",
  "HIGH_RISK",
  "CRITICAL",
] as const;

export type TrustLevelKey = (typeof TRUST_LEVEL_KEYS)[number];

/** Per-tenant GetTenantOverview projection (bigints already narrowed to number). */
export interface TenantOverviewData {
  appCount: number;
  buildCount: number;
  activePolicyCount: number;
  webhookCount: number;
  eventsLast24h: number;
}

/** Per-tenant GetTrustSessionStats projection. */
export interface TrustSessionData {
  totalSessions: number;
  tokensIssued: number;
  attestationsFailed: number;
  sessionsByTrustLevel: Record<string, number>;
}

export type TenantLoadStatus = "ok" | "partial" | "error";

/**
 * Raw per-tenant read result. `overview` and/or `trust` may be absent when the
 * corresponding RPC failed; `errors` carries the human-readable reasons so the
 * UI can degrade gracefully instead of dropping the tenant.
 */
export interface TenantSnapshot {
  tenantId: string;
  status: TenantLoadStatus;
  overview?: TenantOverviewData;
  trust?: TrustSessionData;
  errors: string[];
}

export type HealthBand = "healthy" | "watch" | "at-risk" | "unknown";

/** Per-tenant derived health used for fleet triage. */
export interface TenantHealth {
  tenantId: string;
  status: TenantLoadStatus;
  apps: number;
  events24h: number;
  sessions: number;
  attestationFailureRate: number;
  highRiskRate: number;
  mediumRiskRate: number;
  healthScore: number;
  band: HealthBand;
  errors: string[];
}

/** Fleet-wide aggregate across all managed tenants. */
export interface FleetRollup {
  tenantCount: number;
  healthyTenants: number;
  degradedTenants: number;
  totalApps: number;
  totalBuilds: number;
  totalActivePolicies: number;
  totalWebhooks: number;
  totalEvents24h: number;
  totalSessions: number;
  totalTokensIssued: number;
  totalAttestationsFailed: number;
  sessionsByTrustLevel: Record<TrustLevelKey, number>;
  attestationFailureRate: number;
  highRiskSessionRate: number;
  mediumRiskSessionRate: number;
  tenants: TenantHealth[];
}

/** Narrows a proto int64 (bigint) or number to a finite, non-negative number. */
export function toNum(v: bigint | number | undefined): number {
  if (v === undefined) return 0;
  const n = typeof v === "bigint" ? Number(v) : v;
  if (!Number.isFinite(n) || n < 0) return 0;
  return n;
}

/** Safe ratio in [0,1]; returns 0 when the denominator is zero. */
export function safeRate(numerator: number, denominator: number): number {
  if (denominator <= 0) return 0;
  const r = numerator / denominator;
  if (!Number.isFinite(r) || r < 0) return 0;
  return r > 1 ? 1 : r;
}

function sumTrustLevel(byLevel: Record<string, number>, key: TrustLevelKey): number {
  return toNum(byLevel[key]);
}

/**
 * Maps a tenant's risk rates to a 0–100 health score. Higher is healthier.
 * High-risk sessions weigh more than attestation failures, which weigh more
 * than medium-risk (step-up) sessions. A tenant with no usable data is scored 0
 * and banded "unknown" so it surfaces for the operator rather than silently
 * counting as healthy.
 */
export function tenantHealthScore(input: {
  status: TenantLoadStatus;
  highRiskRate: number;
  attestationFailureRate: number;
  mediumRiskRate: number;
  hasData: boolean;
}): { healthScore: number; band: HealthBand } {
  if (input.status === "error" || !input.hasData) {
    return { healthScore: 0, band: "unknown" };
  }
  const penalty =
    0.6 * input.highRiskRate +
    0.3 * input.attestationFailureRate +
    0.1 * input.mediumRiskRate;
  const score = Math.round(Math.max(0, Math.min(1, 1 - penalty)) * 100);
  let band: HealthBand;
  if (score >= 80) band = "healthy";
  else if (score >= 50) band = "watch";
  else band = "at-risk";
  return { healthScore: score, band };
}

/** Derives a single tenant's health from its raw snapshot. */
export function tenantHealthFromSnapshot(s: TenantSnapshot): TenantHealth {
  const sessions = toNum(s.trust?.totalSessions);
  const tokens = toNum(s.trust?.tokensIssued);
  const failed = toNum(s.trust?.attestationsFailed);
  const byLevel = s.trust?.sessionsByTrustLevel ?? {};
  const highRisk = sumTrustLevel(byLevel, "HIGH_RISK") + sumTrustLevel(byLevel, "CRITICAL");
  const mediumRisk = sumTrustLevel(byLevel, "MEDIUM_RISK");

  const attestationFailureRate = safeRate(failed, tokens);
  const highRiskRate = safeRate(highRisk, sessions);
  const mediumRiskRate = safeRate(mediumRisk, sessions);
  const hasData = s.overview !== undefined || s.trust !== undefined;

  const { healthScore, band } = tenantHealthScore({
    status: s.status,
    highRiskRate,
    attestationFailureRate,
    mediumRiskRate,
    hasData,
  });

  return {
    tenantId: s.tenantId,
    status: s.status,
    apps: toNum(s.overview?.appCount),
    events24h: toNum(s.overview?.eventsLast24h),
    sessions,
    attestationFailureRate,
    highRiskRate,
    mediumRiskRate,
    healthScore,
    band,
    errors: s.errors,
  };
}

function emptyTrustLevels(): Record<TrustLevelKey, number> {
  return { TRUSTED: 0, LOW_RISK: 0, MEDIUM_RISK: 0, HIGH_RISK: 0, CRITICAL: 0 };
}

/**
 * Aggregates per-tenant snapshots into a fleet rollup. Pure and total: missing
 * stats contribute 0, unknown trust-level keys are ignored, and the per-tenant
 * health list is sorted worst-first (lowest health score, ties broken by
 * tenant id) so the operator sees the tenants that need attention at the top.
 */
export function computeFleetRollup(snapshots: TenantSnapshot[]): FleetRollup {
  const byLevel = emptyTrustLevels();
  let totalApps = 0;
  let totalBuilds = 0;
  let totalActivePolicies = 0;
  let totalWebhooks = 0;
  let totalEvents24h = 0;
  let totalSessions = 0;
  let totalTokensIssued = 0;
  let totalAttestationsFailed = 0;
  let healthyTenants = 0;
  let degradedTenants = 0;

  const tenants = snapshots.map(tenantHealthFromSnapshot);

  for (const s of snapshots) {
    if (s.overview) {
      totalApps += toNum(s.overview.appCount);
      totalBuilds += toNum(s.overview.buildCount);
      totalActivePolicies += toNum(s.overview.activePolicyCount);
      totalWebhooks += toNum(s.overview.webhookCount);
      totalEvents24h += toNum(s.overview.eventsLast24h);
    }
    if (s.trust) {
      totalSessions += toNum(s.trust.totalSessions);
      totalTokensIssued += toNum(s.trust.tokensIssued);
      totalAttestationsFailed += toNum(s.trust.attestationsFailed);
      for (const key of TRUST_LEVEL_KEYS) {
        byLevel[key] += sumTrustLevel(s.trust.sessionsByTrustLevel, key);
      }
    }
    if (s.status === "ok") healthyTenants += 1;
    else degradedTenants += 1;
  }

  const highRisk = byLevel.HIGH_RISK + byLevel.CRITICAL;
  const mediumRisk = byLevel.MEDIUM_RISK;

  tenants.sort((a, b) =>
    a.healthScore !== b.healthScore
      ? a.healthScore - b.healthScore
      : a.tenantId.localeCompare(b.tenantId),
  );

  return {
    tenantCount: snapshots.length,
    healthyTenants,
    degradedTenants,
    totalApps,
    totalBuilds,
    totalActivePolicies,
    totalWebhooks,
    totalEvents24h,
    totalSessions,
    totalTokensIssued,
    totalAttestationsFailed,
    sessionsByTrustLevel: byLevel,
    attestationFailureRate: safeRate(totalAttestationsFailed, totalTokensIssued),
    highRiskSessionRate: safeRate(highRisk, totalSessions),
    mediumRiskSessionRate: safeRate(mediumRisk, totalSessions),
    tenants,
  };
}

/** Formats a [0,1] rate as a one-decimal percentage string. */
export function formatRate(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}
