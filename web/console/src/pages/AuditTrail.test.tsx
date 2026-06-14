import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRouterTransport } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import {
  AuditEventSchema,
  ListAuditEventsResponseSchema,
  VerifyAuditChainResponseSchema,
} from "../gen/kseal/v1/compliance_pb";
import { ComplianceService } from "../gen/kseal/v1/compliance_service_pb";
import { AuditTrailPage } from "./AuditTrail";
import { renderWithProviders } from "../test/render";

function event(
  seq: number,
  action: string,
  opts: Partial<{ actorKeyId: string; hash: string }> = {},
) {
  return create(AuditEventSchema, {
    seq: BigInt(seq),
    action,
    actorKeyId: opts.actorKeyId ?? "key-ops",
    resourceType: "policy",
    resourceId: "pol-1",
    createdAt: BigInt(1_700_000_000_000 + seq),
    hash: opts.hash ?? `hash${seq}hashhashhash`,
    metadata: { from: "OBSERVE", to: "BLOCK" },
  });
}

describe("AuditTrailPage", () => {
  it("renders audit entries with an intact chain", async () => {
    const transport = createRouterTransport((router) => {
      router.service(ComplianceService, {
        listAuditEvents: () =>
          create(ListAuditEventsResponseSchema, {
            events: [
              event(2, "policy.activate"),
              event(1, "killswitch.disable"),
            ],
          }),
        verifyAuditChain: () =>
          create(VerifyAuditChainResponseSchema, {
            intact: true,
            verifiedCount: 2n,
          }),
      });
    });

    renderWithProviders(<AuditTrailPage />, { transport, route: "/audit" });

    await waitFor(() =>
      expect(screen.getByText("policy.activate")).toBeInTheDocument(),
    );
    expect(screen.getByText("killswitch.disable")).toBeInTheDocument();
    // metadata is rendered deterministically.
    expect(screen.getAllByText("from=OBSERVE, to=BLOCK").length).toBe(2);
    // no chain-break alert when intact.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("warns when VerifyAuditChain reports a broken hash chain", async () => {
    const transport = createRouterTransport((router) => {
      router.service(ComplianceService, {
        listAuditEvents: () =>
          create(ListAuditEventsResponseSchema, {
            events: [event(1, "policy.activate")],
          }),
        verifyAuditChain: () =>
          create(VerifyAuditChainResponseSchema, {
            intact: false,
            brokenSeq: 1n,
            verifiedCount: 1n,
          }),
      });
    });

    renderWithProviders(<AuditTrailPage />, { transport, route: "/audit" });

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("sequence 1"),
    );
  });

  it("degrades gracefully when the RPC is not deployed", async () => {
    // No ComplianceService registered -> UNIMPLEMENTED.
    const transport = createRouterTransport(() => {});

    renderWithProviders(<AuditTrailPage />, { transport, route: "/audit" });

    await waitFor(() =>
      expect(
        screen.getByText(/audit trail is not available yet/i),
      ).toBeInTheDocument(),
    );
  });

  it("shows a neutral 'verification unavailable' state when only VerifyAuditChain is unimplemented", async () => {
    // listAuditEvents is implemented and returns entries, but verifyAuditChain
    // is not registered -> UNIMPLEMENTED. The audit list must still render and
    // the chain banner must show the neutral unavailable state (not an alert).
    const transport = createRouterTransport((router) => {
      router.service(ComplianceService, {
        listAuditEvents: () =>
          create(ListAuditEventsResponseSchema, {
            events: [event(1, "policy.activate")],
          }),
      });
    });

    renderWithProviders(<AuditTrailPage />, { transport, route: "/audit" });

    await waitFor(() =>
      expect(screen.getByText("policy.activate")).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/not available on this deployment/i),
    ).toBeInTheDocument();
    // Neutral state, never a tamper alert.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("filters by action and reissues the query", async () => {
    const user = userEvent.setup();
    const seen: string[] = [];
    const transport = createRouterTransport((router) => {
      router.service(ComplianceService, {
        verifyAuditChain: () =>
          create(VerifyAuditChainResponseSchema, { intact: true }),
        listAuditEvents(req) {
          seen.push(req.action);
          return create(ListAuditEventsResponseSchema, {
            events: req.action
              ? [event(2, req.action)]
              : [
                  event(1, "policy.activate"),
                  event(2, "killswitch.disable"),
                ],
          });
        },
      });
    });

    renderWithProviders(<AuditTrailPage />, { transport, route: "/audit" });

    await waitFor(() => expect(screen.getAllByRole("row")).toHaveLength(3)); // header + 2

    await user.type(screen.getByLabelText("Action"), "killswitch.disable");

    await waitFor(() => expect(seen).toContain("killswitch.disable"));
    await waitFor(() => {
      const table = screen.getByRole("table");
      expect(
        within(table).getByText("killswitch.disable"),
      ).toBeInTheDocument();
    });
  });
});
