import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRouterTransport } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import { QueryService } from "../gen/kseal/v1/query_service_pb";
import {
  EventRecordSchema,
  ListEventsResponseSchema,
} from "../gen/kseal/v1/query_pb";
import { EventType, TrustLevel } from "../gen/kseal/v1/common_pb";
import { EventsPage } from "./Events";
import { renderWithProviders } from "../test/render";

function record(
  id: string,
  type: EventType,
  risk: TrustLevel,
  ts: number,
) {
  return create(EventRecordSchema, {
    id,
    eventType: type,
    riskLevel: risk,
    timestamp: BigInt(ts),
    appBuildHash: "deadbeefcafef00d",
  });
}

const events = [
  record("a", EventType.ROOT_RISK, TrustLevel.CRITICAL, 3_000),
  record("b", EventType.DEBUGGER, TrustLevel.LOW_RISK, 1_000),
  record("c", EventType.ROOT_RISK, TrustLevel.HIGH_RISK, 2_000),
];

function transportWithEvents() {
  return createRouterTransport(({ service }) => {
    service(QueryService, {
      listEvents() {
        return create(ListEventsResponseSchema, { events });
      },
      getTenantOverview: () => {
        throw new Error("unused");
      },
      getTrustSessionStats: () => {
        throw new Error("unused");
      },
    });
  });
}

describe("EventsPage", () => {
  it("renders fetched events newest-first", async () => {
    renderWithProviders(<EventsPage />, {
      transport: transportWithEvents(),
      route: "/events",
    });

    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(4)); // header + 3
    const rows = screen.getAllByRole("row").slice(1);
    expect(within(rows[0]).getByText("Root / jailbreak")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Root / jailbreak")).toBeInTheDocument();
    expect(within(rows[2]).getByText("Debugger")).toBeInTheDocument();
  });

  it("filters client-side when an event-type chip is toggled", async () => {
    const user = userEvent.setup();
    renderWithProviders(<EventsPage />, {
      transport: transportWithEvents(),
      route: "/events",
    });

    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(4));

    await user.click(screen.getByRole("button", { name: "Debugger" }));

    await waitFor(() =>
      expect(screen.getAllByRole("row")).toHaveLength(2),
    ); // header + 1
    const table = screen.getByRole("table");
    expect(within(table).getByText("Debugger")).toBeInTheDocument();
    expect(
      within(table).queryByText("Root / jailbreak"),
    ).not.toBeInTheDocument();
  });

  it("filters by risk level and clears filters", async () => {
    const user = userEvent.setup();
    renderWithProviders(<EventsPage />, {
      transport: transportWithEvents(),
      route: "/events",
    });
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(4));

    await user.click(screen.getByRole("button", { name: "Critical" }));
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(2));

    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(4));
  });

  it("loads the next page via the next_page_token cursor", async () => {
    const user = userEvent.setup();
    const page1 = [
      record("p1", EventType.ROOT_RISK, TrustLevel.CRITICAL, 3_000),
    ];
    const page2 = [
      record("p2", EventType.DEBUGGER, TrustLevel.LOW_RISK, 1_000),
    ];

    const transport = createRouterTransport(({ service }) => {
      service(QueryService, {
        listEvents(req) {
          // First page returns a cursor; the page it points at returns no
          // further cursor, so "Load more" should disappear afterward.
          return req.pageToken === "cursor-1"
            ? create(ListEventsResponseSchema, { events: page2 })
            : create(ListEventsResponseSchema, {
                events: page1,
                nextPageToken: "cursor-1",
              });
        },
        getTenantOverview: () => {
          throw new Error("unused");
        },
        getTrustSessionStats: () => {
          throw new Error("unused");
        },
      });
    });

    renderWithProviders(<EventsPage />, { transport, route: "/events" });

    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(2)); // header + 1
    const loadMore = screen.getByRole("button", { name: "Load more" });

    await user.click(loadMore);

    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(3)); // header + 2
    const table = screen.getByRole("table");
    expect(within(table).getByText("Debugger")).toBeInTheDocument();
    // Cursor exhausted: the control is gone.
    expect(
      screen.queryByRole("button", { name: "Load more" }),
    ).not.toBeInTheDocument();
  });
});
