import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { create } from "@bufbuild/protobuf";
import { createRouterTransport } from "@connectrpc/connect";
import { QueryService } from "../gen/kseal/v1/query_service_pb";
import {
  EventRecordSchema,
  GetTenantOverviewResponseSchema,
  GetTrustSessionStatsResponseSchema,
} from "../gen/kseal/v1/query_pb";
import { TrustLevel } from "../gen/kseal/v1/common_pb";
import { TenantsPage } from "./Tenants";
import { renderWithProviders } from "../test/render";

const regionByTenant: Record<string, string> = {
  "tenant-a": "US",
  "tenant-b": "DE",
};

function transport() {
  return createRouterTransport(({ service }) => {
    service(QueryService, {
      getTenantOverview(req) {
        return create(GetTenantOverviewResponseSchema, {
          appCount: req.tenantId === "tenant-a" ? 5 : 2,
          recentEvents: [
            create(EventRecordSchema, {
              id: `${req.tenantId}-e1`,
              appId: "app-1",
              riskLevel: TrustLevel.HIGH_RISK,
              timestamp: BigInt(Date.now()),
              countryOrRegion: regionByTenant[req.tenantId],
            }),
          ],
        });
      },
      getTrustSessionStats(req) {
        return create(GetTrustSessionStatsResponseSchema, {
          totalSessions: 50n,
          tokensIssued: 50n,
          attestationsFailed: req.tenantId === "tenant-a" ? 10n : 0n,
          sessionsByTrustLevel: req.tenantId === "tenant-a" ? { HIGH_RISK: 45n } : { TRUSTED: 50n },
        });
      },
      listEvents: () => {
        throw new Error("unused");
      },
    });
  });
}

async function renderTenants() {
  renderWithProviders(<TenantsPage />, { transport: transport(), route: "/tenants" });
  await waitFor(() =>
    expect(screen.getByRole("link", { name: /tenant-a/ })).toBeInTheDocument(),
  );
}

describe("TenantsPage", () => {
  it("lists managed tenants with drill-down links", async () => {
    await renderTenants();
    expect(screen.getByRole("link", { name: /tenant-a/ })).toHaveAttribute("href", "/tenants/tenant-a");
    expect(screen.getByRole("link", { name: /tenant-b/ })).toBeInTheDocument();
  });

  it("filters by search across tenant id", async () => {
    const user = userEvent.setup();
    await renderTenants();
    await user.type(screen.getByLabelText("Search tenants"), "tenant-a");
    await waitFor(() =>
      expect(screen.queryByRole("link", { name: /tenant-b/ })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole("link", { name: /tenant-a/ })).toBeInTheDocument();
  });

  it("filters by health band quick filter", async () => {
    const user = userEvent.setup();
    await renderTenants();
    // tenant-a has high-risk sessions + attestation failures => at-risk.
    await user.click(screen.getByRole("button", { name: "At risk" }));
    await waitFor(() =>
      expect(screen.queryByRole("link", { name: /tenant-b/ })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole("link", { name: /tenant-a/ })).toBeInTheDocument();
  });

  it("persists and re-applies a saved view", async () => {
    const user = userEvent.setup();
    await renderTenants();
    await user.type(screen.getByLabelText("Search tenants"), "tenant-a");
    await user.type(screen.getByLabelText("Save current view"), "Only A");
    await user.click(screen.getByRole("button", { name: "Save" }));

    const select = screen.getByLabelText("Saved views") as HTMLSelectElement;
    await waitFor(() =>
      expect(within(select).getByRole("option", { name: "Only A" })).toBeInTheDocument(),
    );

    // Clear the search, then re-apply the saved view to restore it.
    await user.clear(screen.getByLabelText("Search tenants"));
    await waitFor(() =>
      expect(screen.getByRole("link", { name: /tenant-b/ })).toBeInTheDocument(),
    );
    await user.selectOptions(select, within(select).getByRole("option", { name: "Only A" }));
    await waitFor(() =>
      expect(screen.queryByRole("link", { name: /tenant-b/ })).not.toBeInTheDocument(),
    );
  });

  it("exposes CSV and JSON export actions", async () => {
    await renderTenants();
    const group = screen.getByRole("group", { name: "Export current view" });
    expect(within(group).getByRole("button", { name: "Export CSV" })).toBeEnabled();
    expect(within(group).getByRole("button", { name: "Export JSON" })).toBeEnabled();
  });
});
