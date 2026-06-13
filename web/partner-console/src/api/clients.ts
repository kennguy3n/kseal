import { createClient, type Client, type Transport } from "@connectrpc/connect";
import { QueryService } from "../gen/kseal/v1/query_service_pb";

// The partner console is read-only and fleet rollups are computed entirely in
// the browser, so it needs only the QueryService read surface (per-tenant
// overview + trust-session stats). There is no partner/fleet RPC — aggregation
// across the managed tenant set happens client-side (see lib/rollup.ts).
export interface KsealClients {
  query: Client<typeof QueryService>;
}

export function createClients(transport: Transport): KsealClients {
  return {
    query: createClient(QueryService, transport),
  };
}
