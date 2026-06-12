import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useClients, useSession } from "../state/useAuth";
import type { EventType } from "../gen/kseal/v1/common_pb";

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
  overview: (tenant: string) => ["overview", tenant] as const,
  trustStats: (tenant: string) => ["trustStats", tenant] as const,
  events: (tenant: string, filter: unknown) =>
    ["events", tenant, filter] as const,
};

export function useApps() {
  const clients = useClients();
  const { tenantId } = useSession();
  return useQuery({
    queryKey: queryKeys.apps(tenantId),
    queryFn: async () => {
      const res = await clients.registry.listApps({ tenantId, pageSize: 200 });
      return res.apps;
    },
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
  return useQuery({
    queryKey: queryKeys.builds(tenantId, appId),
    queryFn: async () => {
      const res = await clients.registry.listBuilds({
        tenantId,
        appId,
        pageSize: 100,
      });
      return res.builds;
    },
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
  return useQuery({
    queryKey: queryKeys.events(tenantId, args),
    queryFn: async () => {
      const res = await clients.query.listEvents({
        tenantId,
        appId: args.appId ?? "",
        startTime: BigInt(args.startTime ?? 0),
        endTime: BigInt(args.endTime ?? 0),
        pageSize: 200,
      });
      return res.events;
    },
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

export function useActivatePolicy(appId: string) {
  const clients = useClients();
  const { tenantId } = useSession();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (policyId: string) =>
      clients.registry.activatePolicy({ tenantId, id: policyId }),
    onSuccess: () => {
      void qc.invalidateQueries({
        queryKey: queryKeys.policies(tenantId, appId),
      });
      void qc.invalidateQueries({
        queryKey: queryKeys.activePolicy(tenantId, appId),
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
    },
  });
}
