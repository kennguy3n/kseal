import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useClients, useSession } from "../state/useAuth";
import type { EventType } from "../gen/kseal/v1/common_pb";
import type { SiemKind, SiemPayloadFormat } from "../gen/kseal/v1/siem_pb";

// Server-side page sizes for the keyset-paginated list RPCs. The console loads
// one page at a time and exposes a "Load more" control driven by the response's
// next_page_token, so nothing is ever silently truncated.
const APPS_PAGE_SIZE = 50;
const BUILDS_PAGE_SIZE = 50;
const EVENTS_PAGE_SIZE = 100;

// Centralized query keys, all tenant-scoped so caches never bleed across the
// tenant boundary even if the same client instance is reused.
export const queryKeys = {
  apps: (tenant: string) => ["apps", tenant] as const,
  app: (tenant: string, appId: string) => ["app", tenant, appId] as const,
  builds: (tenant: string, appId: string) => ["builds", tenant, appId] as const,
  policies: (tenant: string, appId: string) =>
    ["policies", tenant, appId] as const,
  activePolicy: (tenant: string, appId: string) =>
    ["activePolicy", tenant, appId] as const,
  webhooks: (tenant: string) => ["webhooks", tenant] as const,
  siemConnectors: (tenant: string) => ["siemConnectors", tenant] as const,
  overview: (tenant: string) => ["overview", tenant] as const,
  trustStats: (tenant: string) => ["trustStats", tenant] as const,
  events: (tenant: string, filter: unknown) =>
    ["events", tenant, filter] as const,
};

export function useApps() {
  const clients = useClients();
  const { tenantId } = useSession();
  return useInfiniteQuery({
    queryKey: queryKeys.apps(tenantId),
    queryFn: async ({ pageParam }) => {
      const res = await clients.registry.listApps({
        tenantId,
        pageSize: APPS_PAGE_SIZE,
        pageToken: pageParam,
      });
      return { items: res.apps, nextPageToken: res.nextPageToken };
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.nextPageToken || undefined,
    select: (data) => data.pages.flatMap((page) => page.items),
  });
}

export function useApp(appId: string) {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: queryKeys.app(tenantId, appId),
    queryFn: async () => {
      const res = await clients.registry.getApp({ tenantId, id: appId });
      return res.app ?? null;
    },
    enabled: appId.length > 0,
  });
}

export function useBuilds(appId: string) {
  const clients = useClients();
  const { tenantId } = useSession();
  return useInfiniteQuery({
    queryKey: queryKeys.builds(tenantId, appId),
    queryFn: async ({ pageParam }) => {
      const res = await clients.registry.listBuilds({
        tenantId,
        appId,
        pageSize: BUILDS_PAGE_SIZE,
        pageToken: pageParam,
      });
      return { items: res.builds, nextPageToken: res.nextPageToken };
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.nextPageToken || undefined,
    select: (data) => data.pages.flatMap((page) => page.items),
    enabled: appId.length > 0,
  });
}

export function usePolicies(appId: string) {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: queryKeys.policies(tenantId, appId),
    queryFn: async () => {
      const res = await clients.registry.listPolicies({ tenantId, appId });
      return res.policies;
    },
  });
}

export function useActivePolicy(appId: string) {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: queryKeys.activePolicy(tenantId, appId),
    queryFn: async () => {
      const res = await clients.registry.getActivePolicy({ tenantId, appId });
      return res.policy ?? null;
    },
  });
}

export function useWebhooks() {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: queryKeys.webhooks(tenantId),
    queryFn: async () => {
      const res = await clients.webhook.listWebhooks({ tenantId });
      return res.webhooks;
    },
  });
}

export function useSiemConnectors() {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: queryKeys.siemConnectors(tenantId),
    queryFn: async () => {
      const res = await clients.siem.listConnectors({ tenantId });
      return res.connectors;
    },
  });
}

// The auth secret is write-only: it is sent on registration and never read
// back, so it is intentionally absent from the connector list type.
export interface RegisterSiemConnectorInput {
  kind: SiemKind;
  endpoint: string;
  authSecret: string;
  fieldAllowList: string[];
  format?: SiemPayloadFormat;
  sentinelDcrImmutableId?: string;
  sentinelStreamName?: string;
  elasticIndex?: string;
  splunkIndex?: string;
  splunkSourcetype?: string;
}

export function useRegisterSiemConnector() {
  const clients = useClients();
  const { tenantId } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: RegisterSiemConnectorInput) =>
      clients.siem.registerConnector({
        tenantId,
        kind: input.kind,
        endpoint: input.endpoint,
        authSecret: input.authSecret,
        format: input.format,
        fieldAllowList: input.fieldAllowList,
        sentinelDcrImmutableId: input.sentinelDcrImmutableId ?? "",
        sentinelStreamName: input.sentinelStreamName ?? "",
        elasticIndex: input.elasticIndex ?? "",
        splunkIndex: input.splunkIndex ?? "",
        splunkSourcetype: input.splunkSourcetype ?? "",
      }),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: queryKeys.siemConnectors(tenantId),
      });
    },
  });
}

export function useDeleteSiemConnector() {
  const clients = useClients();
  const { tenantId } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => clients.siem.deleteConnector({ tenantId, id }),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: queryKeys.siemConnectors(tenantId),
      });
    },
  });
}

export function useTenantOverview() {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: queryKeys.overview(tenantId),
    queryFn: () => clients.query.getTenantOverview({ tenantId }),
  });
}

export function useTrustSessionStats() {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: queryKeys.trustStats(tenantId),
    queryFn: () => clients.query.getTrustSessionStats({ tenantId }),
  });
}

// Only coarse, server-relevant parameters live here. Event-type and risk-level
// refinement is applied client-side (see filterEvents) so toggling those chips
// is instant and does NOT trigger a network round-trip per toggle.
export interface EventsQueryArgs {
  appId?: string;
  startTime?: number;
  endTime?: number;
}

export function useEvents(args: EventsQueryArgs) {
  const clients = useClients();
  const { tenantId } = useSession();
  return useInfiniteQuery({
    queryKey: queryKeys.events(tenantId, args),
    queryFn: async ({ pageParam }) => {
      const res = await clients.query.listEvents({
        tenantId,
        appId: args.appId ?? "",
        startTime: BigInt(args.startTime ?? 0),
        endTime: BigInt(args.endTime ?? 0),
        pageSize: EVENTS_PAGE_SIZE,
        pageToken: pageParam,
      });
      return { items: res.events, nextPageToken: res.nextPageToken };
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.nextPageToken || undefined,
    select: (data) => data.pages.flatMap((page) => page.items),
  });
}

export function useCreatePolicy() {
  const clients = useClients();
  const { tenantId } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: {
      appId: string;
      name: string;
      enforcementMode: number;
      rules: string;
      riskThresholds: string;
      modulesEnabled: string[];
    }) =>
      clients.registry.createPolicy({
        tenantId,
        appId: input.appId,
        name: input.name,
        enforcementMode: input.enforcementMode,
        rules: input.rules,
        riskThresholds: input.riskThresholds,
        modulesEnabled: input.modulesEnabled,
      }),
    onSuccess: (_res, input) => {
      void qc.invalidateQueries({
        queryKey: queryKeys.policies(tenantId, input.appId),
      });
    },
  });
}

// appId travels with each mutation call (not captured by closure) so that if
// the selected app changes while an activation is in-flight, onSuccess still
// invalidates the cache for the app the activation was actually for.
export function useActivatePolicy() {
  const clients = useClients();
  const { tenantId } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { policyId: string; appId: string }) =>
      clients.registry.activatePolicy({ tenantId, id: input.policyId }),
    onSuccess: (_res, input) => {
      void qc.invalidateQueries({
        queryKey: queryKeys.policies(tenantId, input.appId),
      });
      void qc.invalidateQueries({
        queryKey: queryKeys.activePolicy(tenantId, input.appId),
      });
    },
  });
}

export function useRegisterWebhook() {
  const clients = useClients();
  const { tenantId } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: { url: string; eventTypes: EventType[] }) =>
      clients.webhook.registerWebhook({
        tenantId,
        url: input.url,
        eventTypes: input.eventTypes,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.webhooks(tenantId) });
      // The Dashboard reads webhookCount from the overview, so refresh it too.
      void qc.invalidateQueries({ queryKey: queryKeys.overview(tenantId) });
    },
  });
}

export function useDeleteWebhook() {
  const clients = useClients();
  const { tenantId } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => clients.webhook.deleteWebhook({ tenantId, id }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: queryKeys.webhooks(tenantId) });
      // The Dashboard reads webhookCount from the overview, so refresh it too.
      void qc.invalidateQueries({ queryKey: queryKeys.overview(tenantId) });
    },
  });
}
