import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRouterTransport } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import {
  AuditEventSchema,
  AuditService,
  ListAuditEventsResponseSchema,
} from "../gen-local/kseal/consolelocal/v1/compliance_pb";
import { AuditTrailPage } from "./AuditTrail";
import { renderWithProviders } from "../test/render";

function entry(
  id: string,
  sequence: number,
  action: string,
  opts: Partial<{ actor: string; entryHash: string }> = {},
) {
  return create(AuditEventSchema, {
    id,
    sequence: BigInt(sequence),
    action,
    actor: opts.actor ?? "ops@kseal",
    resourceType: "policy",
    resourceId: "pol-1",
    timestamp: BigInt(1_700_000_000_000 + sequence),
    entryHash: opts.entryHash ?? `${id}hashhashhash`,
    metadata: { from: "OBSERVE", to: "BLOCK" },
  });
}

describe("AuditTrailPage", () => {
  it("renders chain-verified audit entries", async () => {
    const transport = createRouterTransport(({ service }) => {
      service(AuditService, {
        listAuditEvents() {
          return create(ListAuditEventsResponseSchema, {
            events: [
              entry("a", 2, "policy.activate"),
              entry("b", 1, "killswitch.disable"),
            ],
            chainVerified: true,
          });
        },
      });
    });

    renderWithProviders(<AuditTrailPage />, { transport, route: "/audit" });

    await waitFor(() =>
      expect(screen.getByText("policy.activate")).toBeInTheDocument(),
    );
    expect(screen.getByText("killswitch.disable")).toBeInTheDocument();
    // metadata is rendered deterministically.
    expect(screen.getAllByText("from=OBSERVE, to=BLOCK").length).toBe(2);
    // no chain-break alert when verified.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("warns when the server reports a broken hash chain", async () => {
    const transport = createRouterTransport(({ service }) => {
      service(AuditService, {
        listAuditEvents() {
          return create(ListAuditEventsResponseSchema, {
            events: [entry("a", 1, "policy.activate")],
            chainVerified: false,
            chainError: "hash mismatch at sequence 1",
          });
        },
      });
    });

    renderWithProviders(<AuditTrailPage />, { transport, route: "/audit" });

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "hash mismatch at sequence 1",
      ),
    );
  });

  it("degrades gracefully when the RPC is not deployed", async () => {
    // No AuditService registered -> UNIMPLEMENTED.
    const transport = createRouterTransport(() => {});

    renderWithProviders(<AuditTrailPage />, { transport, route: "/audit" });

    await waitFor(() =>
      expect(
        screen.getByText(/audit trail is not available yet/i),
      ).toBeInTheDocument(),
    );
  });

  it("filters by actor and reissues the query", async () => {
    const user = userEvent.setup();
    const seen: string[] = [];
    const transport = createRouterTransport(({ service }) => {
      service(AuditService, {
        listAuditEvents(req) {
          seen.push(req.actor);
          return create(ListAuditEventsResponseSchema, {
            events: req.actor
              ? [entry("a", 1, "policy.activate", { actor: req.actor })]
              : [
                  entry("a", 1, "policy.activate"),
                  entry("b", 2, "killswitch.disable", { actor: "admin@kseal" }),
                ],
            chainVerified: true,
          });
        },
      });
    });

    renderWithProviders(<AuditTrailPage />, { transport, route: "/audit" });

    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(3)); // header + 2

    await user.type(screen.getByLabelText("Actor"), "admin@kseal");

    await waitFor(() => expect(seen).toContain("admin@kseal"));
    await waitFor(() => {
      const table = screen.getByRole("table");
      expect(within(table).getByText("admin@kseal")).toBeInTheDocument();
    });
  });
});
