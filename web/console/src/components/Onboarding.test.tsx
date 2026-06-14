import { describe, expect, it } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createRouterTransport } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import {
  GetTenantOverviewResponseSchema,
  GetTrustSessionStatsResponseSchema,
} from "../gen/kseal/v1/query_pb";
import { QueryService } from "../gen/kseal/v1/query_service_pb";
import {
  ListPoliciesResponseSchema,
  PolicySchema,
} from "../gen/kseal/v1/registry_pb";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import {
  AuditEventSchema,
  ListAuditEventsResponseSchema,
} from "../gen/kseal/v1/compliance_pb";
import { ComplianceService } from "../gen/kseal/v1/compliance_service_pb";
import { Onboarding } from "./Onboarding";
import { renderWithProviders, TEST_SESSION } from "../test/render";

// A transport whose responses determine how many onboarding steps are derived
// as complete. Every field defaults to the "not done yet" value.
function buildTransport(opts: {
  appCount?: number;
  tokensIssued?: bigint;
  totalSessions?: bigint;
  hasPolicy?: boolean;
  auditEntries?: bigint;
}) {
  return createRouterTransport((router) => {
    router.service(QueryService, {
      getTenantOverview: () =>
        create(GetTenantOverviewResponseSchema, {
          appCount: opts.appCount ?? 0,
        }),
      getTrustSessionStats: () =>
        create(GetTrustSessionStatsResponseSchema, {
          tokensIssued: opts.tokensIssued ?? 0n,
          totalSessions: opts.totalSessions ?? 0n,
        }),
    });
    router.service(RegistryService, {
      listPolicies: () =>
        create(ListPoliciesResponseSchema, {
          // The onboarding step is satisfied by any active policy across the
          // tenant (tenant-wide or app-scoped), so an active row marks it done.
          policies: opts.hasPolicy
            ? [
                create(PolicySchema, {
                  id: "pol-1",
                  name: "Default",
                  isActive: true,
                }),
              ]
            : [],
        }),
    });
    router.service(ComplianceService, {
      // Onboarding derives "has audit activity" from a single-row probe, so the
      // step is done whenever at least one event exists.
      listAuditEvents: () =>
        create(ListAuditEventsResponseSchema, {
          events:
            (opts.auditEntries ?? 0n) > 0n
              ? [create(AuditEventSchema, { seq: 1n })]
              : [],
        }),
    });
  });
}

describe("Onboarding", () => {
  it("derives step completion from live tenant data", async () => {
    // Two of five steps are satisfied by the data: an app exists and a policy
    // is active.
    const transport = buildTransport({ appCount: 1, hasPolicy: true });

    renderWithProviders(<Onboarding />, { transport });

    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Secure your app" }),
      ).toBeInTheDocument(),
    );

    const progress = screen.getByRole("progressbar");
    expect(progress).toHaveAttribute("aria-valuenow", "2");
    expect(progress).toHaveAttribute("aria-valuemax", "5");
    expect(screen.getByText("2/5")).toBeInTheDocument();
  });

  it("can be dismissed to a resumable banner and resumed", async () => {
    const user = userEvent.setup();
    const transport = buildTransport({ appCount: 1 });

    renderWithProviders(<Onboarding />, { transport });

    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Secure your app" }),
      ).toBeInTheDocument(),
    );

    await user.click(
      screen.getByRole("button", { name: "Dismiss onboarding checklist" }),
    );

    // Collapses to the slim resumable banner, and the preference is persisted.
    const resume = await screen.findByRole("button", { name: "Resume setup" });
    expect(
      screen.queryByRole("heading", { name: "Secure your app" }),
    ).not.toBeInTheDocument();
    expect(
      localStorage.getItem(
        `kseal.console.onboarding.${TEST_SESSION.tenantId}`,
      ),
    ).toContain("true");

    await user.click(resume);
    expect(
      await screen.findByRole("heading", { name: "Secure your app" }),
    ).toBeInTheDocument();
  });

  it("shows a completed state when every step is satisfied", async () => {
    const transport = buildTransport({
      appCount: 2,
      tokensIssued: 5n,
      totalSessions: 3n,
      hasPolicy: true,
      auditEntries: 9n,
    });

    renderWithProviders(<Onboarding />, { transport });

    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Your app is protected" }),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/protection is live/i),
    ).toBeInTheDocument();
    expect(screen.getByText("5/5")).toBeInTheDocument();
  });
});
