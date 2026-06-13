import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { QueryService } from "../gen/kseal/v1/query_service_pb";
import {
  GetTenantOverviewResponseSchema,
  GetTrustSessionStatsResponseSchema,
} from "../gen/kseal/v1/query_pb";
import { FleetOverviewPage } from "./FleetOverview";
import { renderWithProviders } from "../test/render";

// Per-tenant fixtures keyed by tenant id; the router transport dispatches on the
// request's tenantId so the test exercises the real fan-out + aggregation path.
const overview: Record<string, { apps: number; events: number }> = {
  "tenant-a": { apps: 2, events: 100 },
  "tenant-b": { apps: 3, events: 200 },
};
const trust: Record<
  string,
  { sessions: number; tokens: number; failed: number; byLevel: Record<string, bigint> }
> = {
  "tenant-a": { sessions: 50, tokens: 40, failed: 4, byLevel: { TRUSTED: 40n, HIGH_RISK: 10n } },
  "tenant-b": { sessions: 50, tokens: 60, failed: 0, byLevel: { TRUSTED: 50n } },
};

function fleetTransport() {
  return createRouterTransport(({ service }) => {
    service(QueryService, {
      getTenantOverview(req) {
        const o = overview[req.tenantId];
        return create(GetTenantOverviewResponseSchema, {
          appCount: o?.apps ?? 0,
          eventsLast24h: BigInt(o?.events ?? 0),
        });
      },
      getTrustSessionStats(req) {
        const t = trust[req.tenantId];
        return create(GetTrustSessionStatsResponseSchema, {
          totalSessions: BigInt(t?.sessions ?? 0),
          tokensIssued: BigInt(t?.tokens ?? 0),
          attestationsFailed: BigInt(t?.failed ?? 0),
          sessionsByTrustLevel: t?.byLevel ?? {},
        });
      },
      listEvents: () => {
        throw new Error("unused");
      },
    });
  });
}

describe("FleetOverviewPage", () => {
  it("renders aggregated fleet stats across tenants", async () => {
    renderWithProviders(<FleetOverviewPage />, { transport: fleetTransport() });

    await waitFor(() =>
      expect(screen.getByText("Fleet overview")).toBeInTheDocument(),
    );

    // Managed tenants = 2, apps = 5, events = 300, sessions = 100.
    const tenants = screen.getByText("Managed tenants").closest(".card");
    expect(within(tenants as HTMLElement).getByText("2")).toBeInTheDocument();
    const apps = screen.getByText("Apps").closest(".card");
    expect(within(apps as HTMLElement).getByText("5")).toBeInTheDocument();
    const events = screen.getByText("Events (24h)").closest(".card");
    expect(within(events as HTMLElement).getByText("300")).toBeInTheDocument();

    // High-risk session rate = (10+0)/100 = 10.0% (scoped to the rollup card,
    // since per-tenant rows also contain percentages).
    const pressure = screen.getByText("High-risk session rate").closest(".card");
    expect(within(pressure as HTMLElement).getByText("10.0%")).toBeInTheDocument();
  });

  it("lists tenants worst-first in the health table", async () => {
    renderWithProviders(<FleetOverviewPage />, { transport: fleetTransport() });
    await waitFor(() =>
      expect(screen.getByText("Tenant health")).toBeInTheDocument(),
    );
    const table = screen.getByRole("table");
    const rows = within(table).getAllByRole("row").slice(1); // drop header
    // tenant-a has high-risk sessions, so it is less healthy and sorts first.
    expect(within(rows[0]).getByText("tenant-a")).toBeInTheDocument();
    expect(within(rows[1]).getByText("tenant-b")).toBeInTheDocument();
  });

  it("surfaces a degraded-data notice when a tenant read fails", async () => {
    const transport = createRouterTransport(({ service }) => {
      service(QueryService, {
        getTenantOverview(req) {
          if (req.tenantId === "tenant-b")
            throw new ConnectError("overview down", Code.Unavailable);
          return create(GetTenantOverviewResponseSchema, { appCount: 2 });
        },
        getTrustSessionStats() {
          return create(GetTrustSessionStatsResponseSchema, {});
        },
        listEvents: () => {
          throw new Error("unused");
        },
      });
    });

    renderWithProviders(<FleetOverviewPage />, { transport });
    await waitFor(() =>
      expect(
        screen.getByText(/returned\s+incomplete data/i),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText(/overview down/)).toBeInTheDocument();
  });
});
