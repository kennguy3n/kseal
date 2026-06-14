import {
  useInfiniteQuery,
  useQuery,
  type InfiniteData,
} from "@tanstack/react-query";
import { useClients, useSession } from "../state/useAuth";
import type { TrustLevel } from "../gen/kseal/v1/common_pb";
import type { SignalRecord } from "../lib/events";
import { type TenantSnapshot } from "../lib/rollup";
import { fetchTenantSnapshot, toSignalRecord } from "./fleet";

const EVENTS_PAGE_SIZE = 25;

/**
 * Single-tenant snapshot for the drill-down. Shares the exact query key used by
 * the fleet fan-out (`["fleet-tenant", apiBaseUrl, tenantId]`), so opening a
 * tenant reuses the already-cached read instead of refetching.
 */
export function useTenantSnapshot(tenantId: string) {
  const { query } = useClients();
  const { apiBaseUrl } = useSession();
  return useQuery<TenantSnapshot>({
    queryKey: ["fleet-tenant", apiBaseUrl, tenantId] as const,
    queryFn: () => fetchTenantSnapshot(query, tenantId),
    staleTime: 15_000,
  });
}

interface EventPage {
  signals: SignalRecord[];
  nextPageToken: string;
}

export interface UseTenantEventsResult {
  signals: SignalRecord[];
  isLoading: boolean;
  isError: boolean;
  error: unknown;
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  fetchNextPage: () => void;
}

/**
 * Signal-level drill-down: keyset-paginated ListEvents for one tenant, narrowed
 * to SignalRecords and optionally filtered by fused risk level. The auth
 * interceptor scopes the read to the caller's tenant server-side; this is a
 * pure read with no mutation.
 */
export function useTenantEvents(
  tenantId: string,
  riskLevels: TrustLevel[] = [],
): UseTenantEventsResult {
  const { query } = useClients();
  const { apiBaseUrl } = useSession();
  // Stable cache key for the (sorted) risk-level filter.
  const riskKey = [...riskLevels].sort((a, b) => a - b).join(",");

  const q = useInfiniteQuery<
    EventPage,
    Error,
    InfiniteData<EventPage>,
    readonly unknown[],
    string
  >({
    queryKey: ["tenant-events", apiBaseUrl, tenantId, riskKey] as const,
    initialPageParam: "",
    queryFn: async ({ pageParam }) => {
      const res = await query.listEvents({
        tenantId,
        riskLevels,
        pageSize: EVENTS_PAGE_SIZE,
        pageToken: pageParam,
      });
      return {
        signals: res.events.map(toSignalRecord),
        nextPageToken: res.nextPageToken,
      };
    },
    getNextPageParam: (last) => (last.nextPageToken ? last.nextPageToken : undefined),
    staleTime: 15_000,
  });

  const signals = (q.data?.pages ?? []).flatMap((p) => p.signals);

  return {
    signals,
    isLoading: q.isLoading,
    isError: q.isError,
    error: q.error,
    hasNextPage: q.hasNextPage,
    isFetchingNextPage: q.isFetchingNextPage,
    fetchNextPage: () => void q.fetchNextPage(),
  };
}
