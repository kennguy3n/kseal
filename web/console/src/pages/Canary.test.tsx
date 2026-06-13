import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import {
  Code,
  ConnectError,
  createRouterTransport,
  type ConnectRouter,
} from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import { ListAppsResponseSchema } from "../gen/kseal/v1/registry_pb";
import {
  CanaryState,
  CanaryStatusSchema,
  GetCanaryStatusResponseSchema,
} from "../gen/kseal/v1/compliance_pb";
import { ComplianceService } from "../gen/kseal/v1/compliance_service_pb";
import { CanaryPage } from "./Canary";
import { renderWithProviders } from "../test/render";

function withApps(router: ConnectRouter) {
  router.service(RegistryService, {
    listApps: () => create(ListAppsResponseSchema, { apps: [] }),
  });
}

describe("CanaryPage", () => {
  it("renders the active rollout with state, percentage and metrics", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      router.service(ComplianceService, {
        getCanaryStatus() {
          return create(GetCanaryStatusResponseSchema, {
            status: create(CanaryStatusSchema, {
              candidatePolicyId: "block-on-root v3",
              stablePolicyId: "block-on-root v2",
              percent: 25,
              state: CanaryState.ACTIVE,
              blockRate: 0.01,
              rollbackThreshold: 0.05,
              sampleCount: 1000n,
              updatedAt: 1_700_000_000_000n,
            }),
          });
        },
      });
    });

    renderWithProviders(<CanaryPage />, { transport, route: "/canary" });

    await waitFor(() =>
      expect(screen.getByText("block-on-root v3")).toBeInTheDocument(),
    );
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("Auto-rollback armed")).toBeInTheDocument();
    expect(screen.getByText("25%")).toBeInTheDocument();
    // progressbar reflects the staged percentage.
    expect(screen.getByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "25",
    );
  });

  it("surfaces an auto-rolled-back rollout with its reason", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      router.service(ComplianceService, {
        getCanaryStatus: () =>
          create(GetCanaryStatusResponseSchema, {
            status: create(CanaryStatusSchema, {
              candidatePolicyId: "block-on-hook v1",
              percent: 10,
              state: CanaryState.ROLLED_BACK,
              lastEvent: "error rate exceeded baseline",
              updatedAt: 1_700_000_000_000n,
            }),
          }),
      });
    });

    renderWithProviders(<CanaryPage />, { transport, route: "/canary" });

    await waitFor(() =>
      expect(screen.getByText("Rolled back")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/error rate exceeded baseline/i),
    ).toBeInTheDocument();
  });

  it("shows an empty state when there is no rollout", async () => {
    const transport = createRouterTransport((router) => {
      withApps(router);
      router.service(ComplianceService, {
        getCanaryStatus: () => {
          throw new ConnectError("no rollout", Code.NotFound);
        },
      });
    });

    renderWithProviders(<CanaryPage />, { transport, route: "/canary" });

    await waitFor(() =>
      expect(
        screen.getByText(/no staged rollout for this scope/i),
      ).toBeInTheDocument(),
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
