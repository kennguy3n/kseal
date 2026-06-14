// Client-side alert thresholds for the MSSP console. Purely presentational: an
// operator sets bounds and the console highlights tenants that breach them. No
// server change and no mutation — thresholds live in the browser (see
// lib/views.ts for persistence) and are evaluated over the existing reads.

import type { TenantHealth } from "./rollup";
import { formatRate } from "./rollup";

/**
 * Alert bounds. A tenant breaches when ANY enabled bound is crossed. Fields are
 * optional so an operator can enable only the dimensions they care about; an
 * undefined bound is simply not evaluated.
 */
export interface AlertThresholds {
  /** Flag tenants whose health score is below this (0–100). */
  minHealthScore?: number;
  /** Flag tenants whose high-risk session rate exceeds this (0–1). */
  maxHighRiskRate?: number;
  /** Flag tenants whose attestation-failure rate exceeds this (0–1). */
  maxAttestationFailureRate?: number;
}

export const EMPTY_THRESHOLDS: AlertThresholds = Object.freeze({});

export interface ThresholdBreach {
  tenantId: string;
  reasons: string[];
}

function isNum(v: number | undefined): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

/** True when any bound in `t` is enabled. */
export function hasActiveThresholds(t: AlertThresholds): boolean {
  return (
    isNum(t.minHealthScore) ||
    isNum(t.maxHighRiskRate) ||
    isNum(t.maxAttestationFailureRate)
  );
}

/**
 * Evaluates a tenant against the thresholds, returning the list of breached
 * bounds (empty when none). "unknown"/no-data tenants are not flagged on
 * rate-based bounds (their rates are 0 and would be misleading), but a
 * minHealthScore bound DOES catch them since an unknown tenant scores 0 and
 * genuinely warrants attention.
 */
export function evaluateThresholds(
  tenant: Pick<
    TenantHealth,
    "healthScore" | "highRiskRate" | "attestationFailureRate" | "band"
  >,
  t: AlertThresholds,
): string[] {
  const reasons: string[] = [];
  if (isNum(t.minHealthScore) && tenant.healthScore < t.minHealthScore) {
    reasons.push(`health ${tenant.healthScore} < ${t.minHealthScore}`);
  }
  const hasRateData = tenant.band !== "unknown";
  if (
    hasRateData &&
    isNum(t.maxHighRiskRate) &&
    tenant.highRiskRate > t.maxHighRiskRate
  ) {
    reasons.push(
      `high-risk ${formatRate(tenant.highRiskRate)} > ${formatRate(t.maxHighRiskRate)}`,
    );
  }
  if (
    hasRateData &&
    isNum(t.maxAttestationFailureRate) &&
    tenant.attestationFailureRate > t.maxAttestationFailureRate
  ) {
    reasons.push(
      `attest-fail ${formatRate(tenant.attestationFailureRate)} > ${formatRate(t.maxAttestationFailureRate)}`,
    );
  }
  return reasons;
}

export function isBreaching(
  tenant: Parameters<typeof evaluateThresholds>[0],
  t: AlertThresholds,
): boolean {
  return evaluateThresholds(tenant, t).length > 0;
}

/** Counts how many of `tenants` breach the thresholds. */
export function countBreaches(
  tenants: readonly TenantHealth[],
  t: AlertThresholds,
): number {
  if (!hasActiveThresholds(t)) return 0;
  let n = 0;
  for (const tenant of tenants) if (isBreaching(tenant, t)) n += 1;
  return n;
}
