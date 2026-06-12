import { describe, expect, it } from "vitest";
import { createRouterTransport } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import {
  AppSchema,
  ListAppsResponseSchema,
} from "../gen/kseal/v1/registry_pb";
import { Platform } from "../gen/kseal/v1/common_pb";
import { createClients } from "./clients";
import { authInterceptor } from "./transport";

describe("createClients wiring + auth header injection", () => {
  it("routes calls through generated clients and injects the API key", async () => {
    let seenAuth: string | null = null;
    let seenTenant = "";

    const transport = createRouterTransport(
      ({ service }) => {
        service(RegistryService, {
          listApps(req, ctx) {
            seenAuth = ctx.requestHeader.get("Authorization");
            seenTenant = req.tenantId;
            return create(ListAppsResponseSchema, {
              apps: [
                create(AppSchema, {
                  id: "app-1",
                  tenantId: req.tenantId,
                  name: "Checkout",
                  platform: Platform.ANDROID,
                  packageId: "com.example.checkout",
                  status: "active",
                }),
              ],
            });
          },
        });
      },
      { transport: { interceptors: [authInterceptor(() => "ksk_test")] } },
    );

    const clients = createClients(transport);
    const res = await clients.registry.listApps({ tenantId: "tenant-42" });

    expect(res.apps).toHaveLength(1);
    expect(res.apps[0].name).toBe("Checkout");
    expect(res.apps[0].platform).toBe(Platform.ANDROID);
    expect(seenTenant).toBe("tenant-42");
    expect(seenAuth).toBe("Bearer ksk_test");
  });

  it("exposes a client for every kseal service", () => {
    const transport = createRouterTransport(() => {});
    const clients = createClients(transport);
    expect(Object.keys(clients).sort()).toEqual([
      "config",
      "ingest",
      "query",
      "registry",
      "trust",
      "webhook",
    ]);
  });
});
