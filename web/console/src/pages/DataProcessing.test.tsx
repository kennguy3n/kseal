import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { createRouterTransport, type ConnectRouter } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import { ListAppsResponseSchema } from "../gen/kseal/v1/registry_pb";
import {
  DataProcessingRecordSchema,
  DataProcessingRegistryService,
  ListDataProcessingRecordsResponseSchema,
} from "../gen-local/kseal/consolelocal/v1/compliance_pb";
import { DataProcessingPage } from "./DataProcessing";
import { renderWithProviders } from "../test/render";

// AppSelect reads RegistryService.listApps; keep it minimal and empty.
function withApps(router: ConnectRouter) {
  router.service(RegistryService, {
    listApps: () => create(ListAppsResponseSchema, { apps: [] }),
  });
}

function record(id: string, category: string, personalData: boolean) {
  return create(DataProcessingRecordSchema, {
    id,
    category,
    purpose: "Runtime risk scoring",
    retention: "30 days",
    legalBasis: "Legitimate interest",
    personalData,
    dataFields: ["device_integrity", "os_version"],
    updatedAt: 1_700_000_000_000n,
  });
}

describe("DataProcessingPage", () => {
  it("renders data-processing records with personal-data flags", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      router.service(DataProcessingRegistryService, {
        listDataProcessingRecords() {
          return create(ListDataProcessingRecordsResponseSchema, {
            records: [
              record("a", "Device integrity signals", false),
              record("b", "Coarse location", true),
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
      expect(screen.getByText("Device integrity signals")).toBeInTheDocument(),
    );
    expect(screen.getByText("Coarse location")).toBeInTheDocument();
    expect(screen.getByText("Personal data")).toBeInTheDocument();
    expect(screen.getByText("Non-personal")).toBeInTheDocument();
    expect(screen.getAllByText("device_integrity").length).toBeGreaterThan(0);
  });

  it("degrades gracefully when the RPC is not deployed", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      // DataProcessingRegistryService intentionally unregistered.
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
      router.service(DataProcessingRegistryService, {
        listDataProcessingRecords: () =>
          create(ListDataProcessingRecordsResponseSchema, {}),
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
