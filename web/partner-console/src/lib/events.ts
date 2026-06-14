// Pure helpers for the per-tenant "signal" layer of the fleet → tenant → signal
// drill-down. A SignalRecord is the console's narrowed projection of the wire
// EventRecord (proto bigints already converted to numbers; enum fields kept as
// their numeric TrustLevel / EventType values so label mapping stays in
// lib/format.ts). No network and no React here so the bucketing/severity logic
// is unit-testable in isolation.

/** Narrowed projection of a wire EventRecord used by the console. */
export interface SignalRecord {
  id: string;
  appId: string;
  /** Numeric kseal.v1.EventType. */
  eventType: number;
  /** Numeric kseal.v1.TrustLevel (fused risk level). */
  riskLevel: number;
  /** Observed country/region, or "" when the event carried none. */
  region: string;
  /** Event time in unix millis (0 when unknown). */
  timestampMs: number;
}

// TrustLevel numeric values (kseal.v1.TrustLevel) — kept local so this module
// stays free of generated imports. Mirrors proto/kseal/v1/common.proto.
export const TRUST_LEVEL_MEDIUM = 3;
export const TRUST_LEVEL_HIGH = 4;
export const TRUST_LEVEL_CRITICAL = 5;

/** A signal is "elevated" when its fused risk is medium or worse. */
export function isElevated(riskLevel: number): boolean {
  return riskLevel >= TRUST_LEVEL_MEDIUM;
}

/** A signal is "high-risk" when its fused risk is high or critical. */
export function isHighRisk(riskLevel: number): boolean {
  return riskLevel >= TRUST_LEVEL_HIGH;
}

export interface SignalBucket {
  /** Inclusive start of the bucket in unix millis. */
  startMs: number;
  /** Total signals in the bucket. */
  total: number;
  /** Signals with high/critical fused risk in the bucket (see isHighRisk). */
  highRisk: number;
}

/**
 * Buckets signals into `bucketCount` equal time slots spanning the last
 * `spanMs` ending at `nowMs`, oldest bucket first. Signals outside the window
 * are ignored. Pure and total: an empty input yields all-zero buckets so the
 * sparkline always renders a stable shape.
 */
export function bucketSignals(
  signals: readonly SignalRecord[],
  nowMs: number,
  spanMs: number,
  bucketCount: number,
): SignalBucket[] {
  const n = Math.max(1, Math.floor(bucketCount));
  const span = Math.max(1, spanMs);
  const slot = span / n;
  const start = nowMs - span;
  const buckets: SignalBucket[] = Array.from({ length: n }, (_, i) => ({
    startMs: Math.round(start + i * slot),
    total: 0,
    highRisk: 0,
  }));
  for (const s of signals) {
    if (s.timestampMs <= 0 || s.timestampMs < start || s.timestampMs > nowMs) {
      continue;
    }
    let idx = Math.floor((s.timestampMs - start) / slot);
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    buckets[idx].total += 1;
    if (isHighRisk(s.riskLevel)) buckets[idx].highRisk += 1;
  }
  return buckets;
}

/**
 * Derives the most-observed region across a tenant's recent signals. Returns ""
 * when no signal carried a region. Ties broken alphabetically for determinism.
 */
export function primaryRegion(signals: readonly SignalRecord[]): string {
  const counts = new Map<string, number>();
  for (const s of signals) {
    if (!s.region) continue;
    counts.set(s.region, (counts.get(s.region) ?? 0) + 1);
  }
  let best = "";
  let bestN = 0;
  for (const [region, n] of counts) {
    if (n > bestN || (n === bestN && (best === "" || region < best))) {
      best = region;
      bestN = n;
    }
  }
  return best;
}

/** Sorted, de-duplicated list of all regions observed across signals. */
export function observedRegions(signals: readonly SignalRecord[]): string[] {
  const set = new Set<string>();
  for (const s of signals) {
    if (s.region) set.add(s.region);
  }
  return Array.from(set).sort((a, b) => a.localeCompare(b));
}
