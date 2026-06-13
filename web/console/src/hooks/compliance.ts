import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Code, ConnectError } from "@connectrpc/connect";
import { useClients, useSession } from "../state/useAuth";
import { retryUnlessUnavailable } from "../lib/availability";
import type {
  CanaryStatus,
  KillSwitchCommand,
} from "../gen/kseal/v1/compliance_pb";

// Server-side page size for the keyset-paginated audit list. The console loads
// one page at a time and exposes a "Load more" control driven by
// next_page_token, so nothing is ever silently truncated. The canonical
// data-processing registry and canary status RPCs are unpaginated single
// fetches, so they need no page size.
const AUDIT_PAGE_SIZE = 50;

// All keys are tenant-scoped so caches never bleed across the tenant boundary,
// mirroring queryKeys in hooks/queries.ts.
export const complianceKeys = {
  audit: (tenant: string, filter: unknown) =>
    ["audit", tenant, filter] as const,
  auditChain: (tenant: string) => ["auditChain", tenant] as const,
  dataProcessing: (tenant: string) => ["dataProcessing", tenant] as const,
  killSwitch: (tenant: string, appId: string) =>
    ["killSwitch", tenant, appId] as const,
  canary: (tenant: string, appId: string) =>
    ["canary", tenant, appId] as const,
};

export interface AuditQueryArgs {
  action?: string;
  resourceType?: string;
  startTime?: number;
  endTime?: number;
}

export function useAuditEvents(args: AuditQueryArgs) {
  const clients = useClients();
  const { tenantId } = useSession();
  return useInfiniteQuery({
    queryKey: complianceKeys.audit(tenantId, args),
    queryFn: async ({ pageParam }) => {
      const res = await clients.compliance.listAuditEvents({
        tenantId,
        action: args.action ?? "",
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

// The canonical service verifies the chain through a dedicated RPC (rather than
// returning a per-page flag), so the audit view recomputes integrity once per
// tenant alongside the event list. A broken chain surfaces a warning banner.
export function useVerifyAuditChain() {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: complianceKeys.auditChain(tenantId),
    queryFn: () => clients.compliance.verifyAuditChain({ tenantId }),
    retry: retryUnlessUnavailable,
  });
}

export function useDataProcessingRegistry() {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: complianceKeys.dataProcessing(tenantId),
    queryFn: async () => {
      const res = await clients.compliance.getDataProcessingRegistry({
        tenantId,
      });
      return res.records;
    },
    retry: retryUnlessUnavailable,
  });
}

export function useKillSwitchState(appId: string) {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: complianceKeys.killSwitch(tenantId, appId),
    queryFn: () =>
      clients.compliance.getKillSwitchState({ tenantId, appId }),
    retry: retryUnlessUnavailable,
  });
}

// appId travels with each mutation call (not captured by closure) so that if
// the selected app changes while a signed change is in-flight, onSuccess still
// invalidates the cache for the app the change was actually for. Mirrors
// useActivatePolicy in hooks/queries.ts. The control plane signs the kill
// switch server-side (Ed25519); the console only requests the issuance.
export function useIssueKillSwitch() {
  const clients = useClients();
  const { tenantId } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: {
      appId: string;
      command: KillSwitchCommand;
      reason: string;
    }) =>
      clients.compliance.issueKillSwitch({
        tenantId,
        appId: input.appId,
        command: input.command,
        reason: input.reason,
      }),
    onSuccess: (_res, input) => {
      void qc.invalidateQueries({
        queryKey: complianceKeys.killSwitch(tenantId, input.appId),
      });
      // A signed kill-switch change is itself an audited control-plane
      // mutation, so refresh the audit trail too.
      void qc.invalidateQueries({ queryKey: ["audit", tenantId] });
    },
  });
}

// The canonical service reports a single canary status per (tenant, app). When
// no rollout exists the server returns NotFound, which we normalize to null so
// the view renders a clean empty state rather than an error.
export function useCanaryStatus(appId: string) {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery<CanaryStatus | null>({
    queryKey: complianceKeys.canary(tenantId, appId),
    queryFn: async () => {
      try {
        const res = await clients.compliance.getCanaryStatus({
          tenantId,
          appId,
        });
        return res.status ?? null;
      } catch (err) {
        if (err instanceof ConnectError && err.code === Code.NotFound) {
          return null;
        }
        throw err;
      }
    },
    retry: retryUnlessUnavailable,
  });
}
