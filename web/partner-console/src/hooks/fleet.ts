import { useCallback, useMemo } from "react";
import { useQueries } from "@tanstack/react-query";
import { ConnectError, type Client } from "@connectrpc/connect";
import type { QueryService } from "../gen/kseal/v1/query_service_pb";
import { useClients, useSession } from "../state/useAuth";
import {
  computeFleetRollup,
  toNum,
  type FleetRollup,
  type TenantLoadStatus,
  type TenantSnapshot,
} from "../lib/rollup";

type QueryClient = Client<typeof QueryService>;

export interface UseFleetResult {
  rollup: FleetRollup;
  snapshots: TenantSnapshot[];
  isLoading: boolean;
  isFetching: boolean;
  refetch: () => void;
}

function errMessage(err: unknown): string {
  if (err instanceof ConnectError) return err.rawMessage;
  if (err instanceof Error) return err.message;
  return String(err);
}

function toNumberRecord(src: Record<string, bigint>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(src)) out[k] = toNum(v);
  return out;
}

/**
 * Fetches a single tenant's overview + trust-session stats and folds them into a
 * snapshot. Never rejects: each RPC is awaited independently so one failing read
 * degrades that stat (status "partial") rather than dropping the whole tenant,
 * and a tenant whose reads all fail (e.g. the operator key is not authorized for
 * it) becomes an "error" snapshot the UI still lists for triage.
 */
export async function fetchTenantSnapshot(
  client: QueryClient,
  tenantId: string,
): Promise<TenantSnapshot> {
  const [ov, tr] = await Promise.allSettled([
    client.getTenantOverview({ tenantId }),
    client.getTrustSessionStats({ tenantId }),
  ]);

  const errors: string[] = [];
  const snapshot: TenantSnapshot = { tenantId, status: "error", errors };

  if (ov.status === "fulfilled") {
    snapshot.overview = {
      appCount: toNum(ov.value.appCount),
      buildCount: toNum(ov.value.buildCount),
      activePolicyCount: toNum(ov.value.activePolicyCount),
      webhookCount: toNum(ov.value.webhookCount),
      eventsLast24h: toNum(ov.value.eventsLast24h),
    };
  } else {
    errors.push(`overview: ${errMessage(ov.reason)}`);
  }

  if (tr.status === "fulfilled") {
    snapshot.trust = {
      totalSessions: toNum(tr.value.totalSessions),
      tokensIssued: toNum(tr.value.tokensIssued),
      attestationsFailed: toNum(tr.value.attestationsFailed),
      sessionsByTrustLevel: toNumberRecord(tr.value.sessionsByTrustLevel),
    };
  } else {
    errors.push(`trust-stats: ${errMessage(tr.reason)}`);
  }

  const ok = ov.status === "fulfilled";
  const trustOk = tr.status === "fulfilled";
  let status: TenantLoadStatus;
  if (ok && trustOk) status = "ok";
  else if (ok || trustOk) status = "partial";
  else status = "error";
  snapshot.status = status;
  return snapshot;
}

const PLACEHOLDER_ERRORS: string[] = [];

function placeholderSnapshot(tenantId: string): TenantSnapshot {
  // Pre-load placeholder. The UI gates the rollup on isLoading, so this never
  // surfaces as a real "degraded" tenant; it only keeps array indices aligned.
  return { tenantId, status: "partial", errors: PLACEHOLDER_ERRORS };
}

/**
 * Fleet rollup hook: fans out one cached query per managed tenant over the
 * existing per-tenant QueryService reads and aggregates them client-side. The
 * per-tenant queries run in parallel and are cached independently, so a large
 * managed fleet degrades gracefully and re-renders incrementally.
 */
export function useFleet(): UseFleetResult {
  const { query } = useClients();
  const { tenantIds, apiBaseUrl } = useSession();

  const results = useQueries({
    queries: tenantIds.map((tenantId) => ({
      queryKey: ["fleet-tenant", apiBaseUrl, tenantId] as const,
      queryFn: () => fetchTenantSnapshot(query, tenantId),
      staleTime: 15_000,
    })),
  });

  const snapshots = useMemo<TenantSnapshot[]>(
    () => results.map((r, i) => r.data ?? placeholderSnapshot(tenantIds[i])),
    [results, tenantIds],
  );

  const rollup = useMemo(() => computeFleetRollup(snapshots), [snapshots]);

  const isLoading = results.some((r) => r.isLoading);
  const isFetching = results.some((r) => r.isFetching);

  const refetch = useCallback(() => {
    for (const r of results) void r.refetch();
  }, [results]);

  return { rollup, snapshots, isLoading, isFetching, refetch };
}
