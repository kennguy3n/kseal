import { createClient, type Client, type Transport } from "@connectrpc/connect";
import {
  AuditService,
  CanaryService,
  DataProcessingRegistryService,
  KillSwitchService,
} from "../gen-local/kseal/consolelocal/v1/compliance_pb";

// Console-local Connect clients for the compliance/ops RPCs WS-K is adding to
// the canonical server (see proto-local/). They share the authenticated
// transport with the canonical clients and degrade gracefully (UNIMPLEMENTED /
// UNAVAILABLE → "not available yet") until those RPCs are deployed. Kept
// separate from KsealClients so the parent can drop this whole module once the
// console is re-pointed at the canonical kseal.v1 client.
export interface LocalClients {
  audit: Client<typeof AuditService>;
  dataProcessing: Client<typeof DataProcessingRegistryService>;
  killSwitch: Client<typeof KillSwitchService>;
  canary: Client<typeof CanaryService>;
}

export function createLocalClients(transport: Transport): LocalClients {
  return {
    audit: createClient(AuditService, transport),
    dataProcessing: createClient(DataProcessingRegistryService, transport),
    killSwitch: createClient(KillSwitchService, transport),
    canary: createClient(CanaryService, transport),
  };
}
