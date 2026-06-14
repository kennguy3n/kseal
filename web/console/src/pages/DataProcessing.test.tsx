import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { createRouterTransport, type ConnectRouter } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import { ListAppsResponseSchema } from "../gen/kseal/v1/registry_pb";
import {
  DataProcessingRecordSchema,
  GetDataProcessingRegistryResponseSchema,
} from "../gen/kseal/v1/compliance_pb";
import { ComplianceService } from "../gen/kseal/v1/compliance_service_pb";
import { DataProcessingPage } from "./DataProcessing";
import { renderWithProviders } from "../test/render";

// AppSelect reads RegistryService.listApps; keep it minimal and empty.
function withApps(router: ConnectRouter) {
  router.service(RegistryService, {
    listApps: () => create(ListAppsResponseSchema, { apps: [] }),
  });
}

function record(category: string, thirdPartySharing: boolean) {
  return create(DataProcessingRecordSchema, {
    appId: "app-1",
    dataCategories: [category, "os_version"],
    purpose: "Runtime risk scoring",
    retentionDays: 30,
    legalBasis: "Legitimate interest",
    thirdPartySharing,
    updatedAt: 1_700_000_000_000n,
  });
}

describe("DataProcessingPage", () => {
  it("renders data-processing records with third-party-sharing flags", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      router.service(ComplianceService, {
        getDataProcessingRegistry() {
          return create(GetDataProcessingRegistryResponseSchema, {
            records: [
              record("Device integrity signals", false),
              record("Coarse location", true),
            ],
          });
        },
      });
    });

    renderWithProviders(<DataProcessingPage />, {
      transport,
      route: "/data-processing",
    });

    await waitFor(() =>
      expect(
        screen.getByText("Device integrity signals, os_version"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText("Coarse location, os_version"),
    ).toBeInTheDocument();
    expect(screen.getByText("Not shared")).toBeInTheDocument();
    expect(screen.getByText("Shared with third party")).toBeInTheDocument();
    expect(screen.getAllByText("os_version").length).toBeGreaterThan(0);
  });

  it("degrades gracefully when the RPC is not deployed", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      // ComplianceService intentionally unregistered.
    });

    renderWithProviders(<DataProcessingPage />, {
      transport,
      route: "/data-processing",
    });

    await waitFor(() =>
      expect(
        screen.getByText(/data-processing registry is not available yet/i),
      ).toBeInTheDocument(),
    );
  });

  it("shows an empty state when there are no records", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      router.service(ComplianceService, {
        getDataProcessingRegistry: () =>
          create(GetDataProcessingRegistryResponseSchema, {}),
      });
    });

    renderWithProviders(<DataProcessingPage />, {
      transport,
      route: "/data-processing",
    });

    await waitFor(() =>
      expect(
        screen.getByText(/no data-processing records declared/i),
      ).toBeInTheDocument(),
    );
  });
});
