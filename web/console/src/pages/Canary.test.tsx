import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { createRouterTransport, type ConnectRouter } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import { ListAppsResponseSchema } from "../gen/kseal/v1/registry_pb";
import {
  CanaryHealth,
  CanaryMetricsSchema,
  CanaryRolloutSchema,
  CanaryService,
  ListCanaryRolloutsResponseSchema,
} from "../gen-local/kseal/consolelocal/v1/compliance_pb";
import { CanaryPage } from "./Canary";
import { renderWithProviders } from "../test/render";

function withApps(router: ConnectRouter) {
  router.service(RegistryService, {
    listApps: () => create(ListAppsResponseSchema, { apps: [] }),
  });
}

describe("CanaryPage", () => {
  it("renders rollouts with health, percentage and metrics", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      router.service(CanaryService, {
        listCanaryRollouts() {
          return create(ListCanaryRolloutsResponseSchema, {
            rollouts: [
              create(CanaryRolloutSchema, {
                id: "c1",
                policyName: "block-on-root v3",
                percentage: 25,
                health: CanaryHealth.HEALTHY,
                autoRollbackArmed: true,
                updatedAt: 1_700_000_000_000n,
                metrics: create(CanaryMetricsSchema, {
                  sampleEvents: 1000n,
                  cohortInstances: 50n,
                  errorRate: 0.01,
                  baselineErrorRate: 0.012,
                }),
              }),
              create(CanaryRolloutSchema, {
                id: "c2",
                policyName: "block-on-hook v1",
                percentage: 10,
                health: CanaryHealth.ROLLED_BACK,
                rolledBack: true,
                rollbackReason: "error rate exceeded baseline",
                updatedAt: 1_700_000_000_000n,
              }),
            ],
          });
        },
      });
    });

    renderWithProviders(<CanaryPage />, { transport, route: "/canary" });

    await waitFor(() =>
      expect(screen.getByText("block-on-root v3")).toBeInTheDocument(),
    );
    expect(screen.getByText("Healthy")).toBeInTheDocument();
    expect(screen.getByText("Auto-rollback armed")).toBeInTheDocument();
    expect(screen.getByText("25%")).toBeInTheDocument();
    expect(screen.getByText("Auto-rolled back")).toBeInTheDocument();
    expect(
      screen.getByText(/error rate exceeded baseline/i),
    ).toBeInTheDocument();
    // progressbar reflects the staged percentage.
    expect(screen.getAllByRole("progressbar")[0]).toHaveAttribute(
      "aria-valuenow",
      "25",
    );
  });

  it("degrades gracefully when the RPC is not deployed", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
    });

    renderWithProviders(<CanaryPage />, { transport, route: "/canary" });

    await waitFor(() =>
      expect(
        screen.getByText(/canary monitor is not available yet/i),
      ).toBeInTheDocument(),
    );
  });
});
