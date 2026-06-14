import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router-dom";
import { create } from "@bufbuild/protobuf";
import { createRouterTransport } from "@connectrpc/connect";
import { QueryService } from "../gen/kseal/v1/query_service_pb";
import {
  EventRecordSchema,
  GetTenantOverviewResponseSchema,
  GetTrustSessionStatsResponseSchema,
  ListEventsResponseSchema,
} from "../gen/kseal/v1/query_pb";
import { EventType, TrustLevel } from "../gen/kseal/v1/common_pb";
import { TenantDetailPage } from "./TenantDetail";
import { renderWithProviders } from "../test/render";

function transport(
  listCalls: { last?: TrustLevel[] } = {},
  counts: { overview: number; list: number } = { overview: 0, list: 0 },
) {
  return createRouterTransport(({ service }) => {
    service(QueryService, {
      getTenantOverview() {
        counts.overview += 1;
        return create(GetTenantOverviewResponseSchema, {
          appCount: 4,
          buildCount: 9,
          eventsLast24h: 12n,
          recentEvents: [
            create(EventRecordSchema, {
              id: "r1",
              appId: "app-77",
              riskLevel: TrustLevel.HIGH_RISK,
              timestamp: BigInt(Date.now()),
              countryOrRegion: "US",
            }),
          ],
        });
      },
      getTrustSessionStats() {
        return create(GetTrustSessionStatsResponseSchema, {
          totalSessions: 40n,
          tokensIssued: 40n,
          attestationsFailed: 2n,
          sessionsByTrustLevel: { TRUSTED: 30n, HIGH_RISK: 10n },
        });
      },
      listEvents(req) {
        counts.list += 1;
        listCalls.last = req.riskLevels;
        return create(ListEventsResponseSchema, {
          events: [
            create(EventRecordSchema, {
              id: "evt-77",
              appId: "app-77",
              eventType: EventType.ROOT_RISK,
              riskLevel: TrustLevel.CRITICAL,
              timestamp: BigInt(Date.UTC(2026, 0, 1)),
              countryOrRegion: "US",
            }),
          ],
          nextPageToken: "",
        });
      },
    });
  });
}

function renderDetail(route: string, t = transport()) {
  return renderWithProviders(
    <Routes>
      <Route path="/tenants/:tenantId" element={<TenantDetailPage />} />
    </Routes>,
    { transport: t, route },
  );
}

describe("TenantDetailPage", () => {
  it("renders KPIs, derived health, and the signal drill-down", async () => {
    renderDetail("/tenants/tenant-a");
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "tenant-a" })).toBeInTheDocument(),
    );
    // KPI: builds = 9.
    const builds = screen.getByText("Builds").closest(".card");
    expect(within(builds as HTMLElement).getByText("9")).toBeInTheDocument();

    // The signal from listEvents is rendered in the signals table.
    await waitFor(() =>
      expect(screen.getByText("app-77")).toBeInTheDocument(),
    );
    expect(screen.getAllByText("US").length).toBeGreaterThan(0);
  });

  it("refetches signals scoped to the selected risk level", async () => {
    const calls: { last?: TrustLevel[] } = {};
    renderDetail("/tenants/tenant-a", transport(calls));
    await waitFor(() => expect(screen.getByText("app-77")).toBeInTheDocument());
    expect(calls.last).toEqual([]);

    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Critical" }));
    await waitFor(() => expect(calls.last).toEqual([TrustLevel.CRITICAL]));
  });

  it("shows a clear message for a tenant outside the managed fleet and issues no reads", async () => {
    const counts = { overview: 0, list: 0 };
    renderDetail("/tenants/tenant-z", transport({}, counts));
    await waitFor(() =>
      expect(screen.getByText("Tenant not in your fleet")).toBeInTheDocument(),
    );
    // The drill-down must not read a tenant the operator does not manage.
    expect(counts.overview).toBe(0);
    expect(counts.list).toBe(0);
  });
});
