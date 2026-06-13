import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useLocalClients, useSession } from "../state/useAuth";
import { retryUnlessUnavailable } from "../lib/availability";
import type { KillSwitchStatus } from "../gen-local/kseal/consolelocal/v1/compliance_pb";

// Server-side page sizes for the keyset-paginated console-local list RPCs. As
// with the canonical list views, the console loads one page at a time and
// exposes a "Load more" control driven by next_page_token, so nothing is ever
// silently truncated.
const AUDIT_PAGE_SIZE = 50;
const DATA_PROCESSING_PAGE_SIZE = 100;
const CANARY_PAGE_SIZE = 50;

// All keys are tenant-scoped so caches never bleed across the tenant boundary,
// mirroring queryKeys in hooks/queries.ts.
export const complianceKeys = {
  audit: (tenant: string, filter: unknown) =>
    ["audit", tenant, filter] as const,
  dataProcessing: (tenant: string, appId: string) =>
    ["dataProcessing", tenant, appId] as const,
  killSwitch: (tenant: string, appId: string) =>
    ["killSwitch", tenant, appId] as const,
  canary: (tenant: string, appId: string) =>
    ["canary", tenant, appId] as const,
};

export interface AuditQueryArgs {
  actions?: string[];
  actor?: string;
  resourceType?: string;
  startTime?: number;
  endTime?: number;
}

export function useAuditEvents(args: AuditQueryArgs) {
  const clients = useLocalClients();
  const { tenantId } = useSession();
  return useInfiniteQuery({
    queryKey: complianceKeys.audit(tenantId, args),
    queryFn: async ({ pageParam }) => {
      const res = await clients.audit.listAuditEvents({
        tenantId,
        actions: args.actions ?? [],
        actor: args.actor ?? "",
        resourceType: args.resourceType ?? "",
        startTime: BigInt(args.startTime ?? 0),
        endTime: BigInt(args.endTime ?? 0),
        pageSize: AUDIT_PAGE_SIZE,
        pageToken: pageParam,
      });
      return res;
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.nextPageToken || undefined,
    retry: retryUnlessUnavailable,
  });
}

export function useDataProcessingRecords(appId: string) {
  const clients = useLocalClients();
  const { tenantId } = useSession();
  return useInfiniteQuery({
    queryKey: complianceKeys.dataProcessing(tenantId, appId),
    queryFn: async ({ pageParam }) => {
      const res = await clients.dataProcessing.listDataProcessingRecords({
        tenantId,
        appId,
        pageSize: DATA_PROCESSING_PAGE_SIZE,
        pageToken: pageParam,
      });
      return { items: res.records, nextPageToken: res.nextPageToken };
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.nextPageToken || undefined,
    select: (data) => data.pages.flatMap((page) => page.items),
    retry: retryUnlessUnavailable,
  });
}

export function useKillSwitchState(appId: string) {
  const clients = useLocalClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: complianceKeys.killSwitch(tenantId, appId),
    queryFn: async () => {
      const res = await clients.killSwitch.getKillSwitchState({
        tenantId,
        appId,
      });
      return res.state ?? null;
    },
    retry: retryUnlessUnavailable,
  });
}

export function useRequestKillSwitchChange(appId: string) {
  const clients = useLocalClients();
  const { tenantId } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { desiredStatus: KillSwitchStatus; reason: string }) =>
      clients.killSwitch.requestKillSwitchChange({
        tenantId,
        appId,
        desiredStatus: input.desiredStatus,
        reason: input.reason,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: complianceKeys.killSwitch(tenantId, appId),
      });
      // A signed kill-switch change is itself an audited control-plane
      // mutation, so refresh the audit trail too.
      void qc.invalidateQueries({ queryKey: ["audit", tenantId] });
    },
  });
}

export function useCanaryRollouts(appId: string) {
  const clients = useLocalClients();
  const { tenantId } = useSession();
  return useInfiniteQuery({
    queryKey: complianceKeys.canary(tenantId, appId),
    queryFn: async ({ pageParam }) => {
      const res = await clients.canary.listCanaryRollouts({
        tenantId,
        appId,
        pageSize: CANARY_PAGE_SIZE,
        pageToken: pageParam,
      });
      return { items: res.rollouts, nextPageToken: res.nextPageToken };
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.nextPageToken || undefined,
    select: (data) => data.pages.flatMap((page) => page.items),
    retry: retryUnlessUnavailable,
  });
}
