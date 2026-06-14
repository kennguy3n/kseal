import { describe, expect, it } from "vitest";
import { axe, toHaveNoViolations } from "jest-axe";
import { createRouterTransport } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import {
  GetTenantOverviewResponseSchema,
  GetTrustSessionStatsResponseSchema,
} from "../gen/kseal/v1/query_pb";
import { QueryService } from "../gen/kseal/v1/query_service_pb";
import {
  GetActivePolicyResponseSchema,
  PolicySchema,
} from "../gen/kseal/v1/registry_pb";
import { RegistryService } from "../gen/kseal/v1/registry_service_pb";
import {
  ListAuditEventsResponseSchema,
  VerifyAuditChainResponseSchema,
} from "../gen/kseal/v1/compliance_pb";
import { ComplianceService } from "../gen/kseal/v1/compliance_service_pb";
import { renderWithProviders } from "./render";
import { Onboarding } from "../components/Onboarding";
import { LoginPage } from "../pages/Login";
import { AuditTrailPage } from "../pages/AuditTrail";

expect.extend(toHaveNoViolations);

// Automated WCAG checks (labels, roles, names, structure) on representative
// surfaces. jsdom can't compute layout, so color-contrast is disabled here and
// covered by the design-token palette instead.
const axeOptions = { rules: { "color-contrast": { enabled: false } } };

describe("accessibility", () => {
  it("the login screen has no detectable a11y violations", async () => {
    const transport = createRouterTransport(() => {});
    const { container } = renderWithProviders(<LoginPage />, {
      transport,
      route: "/login",
    });
    expect(await axe(container, axeOptions)).toHaveNoViolations();
  });

  it("the onboarding checklist has no detectable a11y violations", async () => {
    const transport = createRouterTransport((router) => {
      router.service(QueryService, {
        getTenantOverview: () =>
          create(GetTenantOverviewResponseSchema, { appCount: 1 }),
        getTrustSessionStats: () =>
          create(GetTrustSessionStatsResponseSchema, {
            tokensIssued: 0n,
            totalSessions: 0n,
          }),
      });
      router.service(RegistryService, {
        getActivePolicy: () =>
          create(GetActivePolicyResponseSchema, {
            policy: create(PolicySchema, { id: "pol-1", name: "Default" }),
          }),
      });
      router.service(ComplianceService, {
        verifyAuditChain: () =>
          create(VerifyAuditChainResponseSchema, { intact: true }),
      });
    });

    const { container, findByRole } = renderWithProviders(<Onboarding />, {
      transport,
    });
    await findByRole("heading", { name: "Secure your app" });
    expect(await axe(container, axeOptions)).toHaveNoViolations();
  });

  it("the audit trail (chain unavailable) has no detectable a11y violations", async () => {
    const transport = createRouterTransport((router) => {
      router.service(ComplianceService, {
        listAuditEvents: () =>
          create(ListAuditEventsResponseSchema, { events: [] }),
      });
    });
    const { container, findByText } = renderWithProviders(<AuditTrailPage />, {
      transport,
      route: "/audit",
    });
    await findByText(/not available on this deployment/i);
    expect(await axe(container, axeOptions)).toHaveNoViolations();
  });
});
