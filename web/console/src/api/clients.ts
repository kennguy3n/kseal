import { createClient, type Client, type Transport } from "@connectrpc/connect";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import { ConfigService } from "../gen/kseal/v1/config_service_pb";
import { TrustService } from "../gen/kseal/v1/trust_service_pb";
import { IngestService } from "../gen/kseal/v1/ingest_service_pb";
import { WebhookService } from "../gen/kseal/v1/webhook_service_pb";
import { QueryService } from "../gen/kseal/v1/query_service_pb";
import { SiemService } from "../gen/kseal/v1/siem_service_pb";

// Typed Connect clients for every kseal service, all generated from the
// canonical protos. QueryService is the read surface (events, tenant overview,
// trust-session stats) backing the Dashboard and Events pages.
export interface KsealClients {
  registry: Client<typeof RegistryService>;
  config: Client<typeof ConfigService>;
  trust: Client<typeof TrustService>;
  ingest: Client<typeof IngestService>;
  webhook: Client<typeof WebhookService>;
  query: Client<typeof QueryService>;
  siem: Client<typeof SiemService>;
}

export function createClients(transport: Transport): KsealClients {
  return {
    registry: createClient(RegistryService, transport),
    config: createClient(ConfigService, transport),
    trust: createClient(TrustService, transport),
    ingest: createClient(IngestService, transport),
    webhook: createClient(WebhookService, transport),
    query: createClient(QueryService, transport),
    siem: createClient(SiemService, transport),
  };
}
